# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0

"""Confirmation-key diagnostics and controlled HMAC key rotation.

This module patches the protected CRUD confirmation helpers during package
initialization. The repository already uses a hardened facade to replace core
CRUD helpers, so the patch remains inside the same security boundary while
keeping the change isolated and testable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Mapping

from analytics_mcp.tools.admin import crud_safety as _safety

_CONFIRMATION_TOKEN_VERSION = 2
_PROCESS_INSTANCE_ID = secrets.token_hex(8)
_PREVIOUS_SECRET_ENVIRONMENT_VARIABLE = (
    "GOOGLE_ANALYTICS_CONFIRMATION_PREVIOUS_SECRET"
)


def _secret_format_warnings(raw: str) -> list[str]:
    """Returns non-secret configuration warnings for a secret value."""
    warnings: list[str] = []
    if raw and raw != raw.strip():
        warnings.append("SURROUNDING_WHITESPACE")
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
        warnings.append("WRAPPING_QUOTES")
    return warnings


def _confirmation_key_id(secret: bytes) -> str:
    """Returns a non-secret identifier for a confirmation signing key."""
    material = b"google-analytics-mcp-confirmation-key:v1:" + secret
    return hashlib.sha256(material).hexdigest()[:16]


def _current_confirmation_secret() -> bytes:
    """Returns the current signing secret using the existing validation rule."""
    return _safety._confirmation_secret()


def _previous_confirmation_secret() -> bytes | None:
    """Returns a valid previous secret during a controlled rotation window."""
    raw = os.getenv(_PREVIOUS_SECRET_ENVIRONMENT_VARIABLE, "")
    if not raw:
        return None
    secret = raw.encode("utf-8")
    if len(secret) < _safety._CONFIRMATION_SECRET_MINIMUM_BYTES:
        return None
    current = _current_confirmation_secret()
    if hmac.compare_digest(secret, current):
        return None
    return secret


def _confirmation_secret_metadata() -> Dict[str, Any]:
    """Returns secret-safe metadata for current and previous signing keys."""
    current_raw = os.getenv("GOOGLE_ANALYTICS_CONFIRMATION_SECRET", "")
    previous_raw = os.getenv(_PREVIOUS_SECRET_ENVIRONMENT_VARIABLE, "")
    current = current_raw.encode("utf-8")
    previous = previous_raw.encode("utf-8")
    minimum = _safety._CONFIRMATION_SECRET_MINIMUM_BYTES
    current_valid = len(current) >= minimum
    previous_valid = bool(previous_raw) and len(previous) >= minimum
    current_key_id = _confirmation_key_id(current) if current_valid else None
    previous_key_id = _confirmation_key_id(previous) if previous_valid else None
    if previous_key_id == current_key_id:
        previous_key_id = None

    return {
        "confirmation_secret_configured": current_valid,
        "confirmation_secret_minimum_bytes": minimum,
        "confirmation_key_id": current_key_id,
        "confirmation_secret_format_warnings": _secret_format_warnings(
            current_raw
        ),
        "previous_confirmation_secret_configured": bool(previous_raw),
        "previous_confirmation_secret_valid": previous_valid,
        "previous_confirmation_key_id": previous_key_id,
        "previous_confirmation_secret_format_warnings": (
            _secret_format_warnings(previous_raw)
        ),
    }


def _verification_keys() -> list[tuple[str, str, bytes]]:
    """Returns current and optional previous keys in verification order."""
    current = _current_confirmation_secret()
    keys = [("current", _confirmation_key_id(current), current)]
    previous = _previous_confirmation_secret()
    if previous is not None:
        keys.append(("previous", _confirmation_key_id(previous), previous))
    return keys


def safety_status_payload(
    config: _safety.SafetyConfig | None = None,
) -> Dict[str, Any]:
    """Returns the existing safety status with key and instance diagnostics."""
    payload = _ORIGINAL_SAFETY_STATUS_PAYLOAD(config)
    payload.update(
        {
            "process_instance_id": _PROCESS_INSTANCE_ID,
            **_confirmation_secret_metadata(),
            "confirmation_token_version": _CONFIRMATION_TOKEN_VERSION,
            "cross_instance_valid": None,
            "cross_instance_requirement": "MATCHING_CONFIRMATION_KEY_ID",
        }
    )
    return payload


async def analytics_safety_status() -> Dict[str, Any]:
    """Reports current mutation safety settings without Google API calls."""
    return safety_status_payload()


def issue_confirmation(
    normalized_payload: Mapping[str, Any],
    property_id: str,
    ttl_seconds: int,
) -> Dict[str, Any]:
    """Issues a versioned HMAC receipt bound to a non-secret key ID."""
    digest = _safety.operation_hash(normalized_payload)
    issued_at = int(time.time())
    expires_at = issued_at + ttl_seconds
    secret = _current_confirmation_secret()
    key_id = _confirmation_key_id(secret)
    token_payload: Dict[str, Any] = {
        "exp": expires_at,
        "hash": digest,
        "iat": issued_at,
        "iid": _PROCESS_INSTANCE_ID,
        "kid": key_id,
        "nonce": _safety._b64url_encode(secrets.token_bytes(12)),
        "pid": property_id,
        "v": _CONFIRMATION_TOKEN_VERSION,
        "verb": "EXECUTE",
    }
    account_id = normalized_payload.get("account_id")
    if isinstance(account_id, str) and account_id:
        token_payload["aid"] = account_id
    parent_hash = normalized_payload.get("property_parent_precondition_hash")
    if isinstance(parent_hash, str) and parent_hash:
        token_payload["pph"] = parent_hash

    encoded_payload = _safety._b64url_encode(
        _safety.canonical_json(token_payload).encode("utf-8")
    )
    signature = _safety._b64url_encode(
        hmac.new(
            secret,
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    confirmation = f"EXECUTE {digest}.{encoded_payload}.{signature}"
    return {
        "operation_hash": digest,
        "operation_hash_version": _safety._HASH_VERSION,
        "confirmation_token_version": _CONFIRMATION_TOKEN_VERSION,
        "confirmation_key_id": key_id,
        "confirmation_issued_by_process_instance_id": _PROCESS_INSTANCE_ID,
        "required_confirmation": confirmation,
        "confirmation_expires_at_epoch": expires_at,
        "validation_receipt": {
            "expires_at_epoch": expires_at,
            "confirmation_key_id": key_id,
            "issued_by_process_instance_id": _PROCESS_INSTANCE_ID,
            "cross_instance_valid": None,
            "cross_instance_requirement": "MATCHING_CONFIRMATION_KEY_ID",
            "replay_protection": "BEST_EFFORT_PROCESS_LOCAL",
            "globally_single_use": False,
        },
    }


def _decode_confirmation_payload(encoded_payload: str) -> Dict[str, Any]:
    """Decodes the untrusted payload only to select a verification key."""
    decoded = _safety._b64url_decode_canonical(encoded_payload)
    try:
        payload = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _safety.CrudSafetyError(
            "INVALID_CONFIRMATION", "Confirmation payload is invalid."
        ) from exc
    if not isinstance(payload, dict):
        raise _safety.CrudSafetyError(
            "INVALID_CONFIRMATION",
            "Confirmation payload must be a JSON object.",
        )
    return payload


def _select_confirmation_key(
    payload: Mapping[str, Any],
    encoded_payload: str,
    signature: str,
) -> tuple[str, str]:
    """Selects and verifies the current or previous configured key."""
    keys = _verification_keys()
    observed_key_id = payload.get("kid")
    if observed_key_id is not None:
        if not isinstance(observed_key_id, str) or not observed_key_id:
            raise _safety.CrudSafetyError(
                "INVALID_CONFIRMATION",
                "Confirmation key identifier is invalid.",
            )
        matching = [item for item in keys if item[1] == observed_key_id]
        if not matching:
            raise _safety.CrudSafetyError(
                "CONFIRMATION_KEY_MISMATCH",
                "Confirmation was signed by a different configured key.",
                {
                    "observed_confirmation_key_id": observed_key_id,
                    "current_confirmation_key_id": keys[0][1],
                    "previous_confirmation_key_id": (
                        keys[1][1] if len(keys) > 1 else None
                    ),
                    "verification_process_instance_id": _PROCESS_INSTANCE_ID,
                },
            )
        candidates = matching
    else:
        # Compatibility for version-1 receipts issued before key IDs existed.
        candidates = keys

    for source, key_id, secret in candidates:
        expected_signature = _safety._b64url_encode(
            hmac.new(
                secret,
                encoded_payload.encode("ascii"),
                hashlib.sha256,
            ).digest()
        )
        if hmac.compare_digest(signature, expected_signature):
            return source, key_id

    raise _safety.CrudSafetyError(
        "INVALID_CONFIRMATION",
        "Confirmation signature is invalid for the declared key.",
        {
            "observed_confirmation_key_id": observed_key_id,
            "verification_process_instance_id": _PROCESS_INSTANCE_ID,
        },
    )


def _verify_confirmation(
    confirmation: str,
    normalized_payload: Mapping[str, Any],
    property_id: str,
    *,
    register_replay: bool,
) -> Dict[str, Any]:
    """Verifies a receipt and optionally registers process-local replay state."""
    try:
        verb, token = confirmation.split(" ", 1)
        digest, encoded_payload, signature = token.split(".", 2)
    except ValueError as exc:
        raise _safety.CrudSafetyError(
            "INVALID_CONFIRMATION",
            "Confirmation must use 'EXECUTE <hash>.<payload>.<signature>'.",
        ) from exc
    if verb != "EXECUTE" or not _safety._HASH_RE.fullmatch(digest):
        raise _safety.CrudSafetyError(
            "INVALID_CONFIRMATION",
            "Confirmation prefix or hash is invalid.",
        )

    payload = _decode_confirmation_payload(encoded_payload)
    key_source, verified_key_id = _select_confirmation_key(
        payload, encoded_payload, signature
    )

    token_version = payload.get("v")
    if token_version not in {1, _CONFIRMATION_TOKEN_VERSION}:
        raise _safety.CrudSafetyError(
            "INVALID_CONFIRMATION",
            "Confirmation token version is not supported.",
            {"confirmation_token_version": token_version},
        )

    expected_hash = _safety.operation_hash(normalized_payload)
    now = int(time.time())
    expected = {
        "hash": expected_hash,
        "pid": property_id,
        "verb": "EXECUTE",
    }
    observed = {key: payload.get(key) for key in expected}

    expected_account = normalized_payload.get("account_id")
    expected_parent_hash = normalized_payload.get(
        "property_parent_precondition_hash"
    )
    if expected_account is not None and payload.get("aid") != expected_account:
        raise _safety.CrudSafetyError(
            "PROPERTY_PARENT_ACCOUNT_CHANGED",
            "The property parent account changed after validation.",
            {
                "expected_account_id": payload.get("aid"),
                "observed_account_id": expected_account,
            },
        )
    if (
        expected_parent_hash is not None
        and payload.get("pph") != expected_parent_hash
    ):
        raise _safety.CrudSafetyError(
            "PROPERTY_PARENT_ACCOUNT_CHANGED",
            "The property parent account changed after validation.",
        )

    if digest != expected_hash or observed != expected:
        raise _safety.CrudSafetyError(
            "CONFIRMATION_MISMATCH",
            "Confirmation does not match the normalized operation payload.",
            {"expected": expected, "observed": observed},
        )
    if not isinstance(payload.get("exp"), int) or payload["exp"] < now:
        raise _safety.CrudSafetyError(
            "CONFIRMATION_EXPIRED",
            "Confirmation has expired and the operation must be revalidated.",
        )
    if not isinstance(payload.get("iat"), int) or payload["iat"] > now + 60:
        raise _safety.CrudSafetyError(
            "INVALID_CONFIRMATION", "Confirmation issue time is invalid."
        )
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise _safety.CrudSafetyError(
            "INVALID_CONFIRMATION", "Confirmation nonce is missing."
        )

    fingerprint = hashlib.sha256(confirmation.encode("utf-8")).hexdigest()[:16]
    if register_replay:
        with _safety._REPLAY_LOCK:
            _safety._purge_replay_cache(now)
            if fingerprint in _safety._USED_CONFIRMATIONS:
                raise _safety.CrudSafetyError(
                    "CONFIRMATION_REPLAYED",
                    "Confirmation was already registered by this process.",
                )
            _safety._USED_CONFIRMATIONS[fingerprint] = payload["exp"]

    return {
        "confirmation_verified": True,
        "confirmation_registered_before_api_call": register_replay,
        "confirmation_token_fingerprint": fingerprint,
        "confirmation_token_version": token_version,
        "confirmation_key_id": verified_key_id,
        "confirmation_key_source": key_source,
        "confirmation_issued_by_process_instance_id": payload.get("iid"),
        "confirmation_verified_by_process_instance_id": _PROCESS_INSTANCE_ID,
        "operation_hash": expected_hash,
        "operation_hash_version": _safety._HASH_VERSION,
    }


def verify_and_register_confirmation(
    confirmation: str,
    normalized_payload: Mapping[str, Any],
    property_id: str,
) -> Dict[str, Any]:
    """Verifies and registers a confirmation before an API call."""
    return _verify_confirmation(
        confirmation,
        normalized_payload,
        property_id,
        register_replay=True,
    )


async def analytics_confirmation_diagnostics() -> Dict[str, Any]:
    """Runs a local confirmation round trip without Google API calls."""
    synthetic_payload = {
        "property_id": "diagnostic",
        "account_id": "diagnostic",
        "property_parent_precondition_hash": "0" * 64,
        "operations": [],
        "atomic": False,
        "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
    }
    issued = issue_confirmation(synthetic_payload, "diagnostic", 60)
    verified = _verify_confirmation(
        issued["required_confirmation"],
        synthetic_payload,
        "diagnostic",
        register_replay=False,
    )
    metadata = _confirmation_secret_metadata()
    return {
        "runtime": "PYTHON_FASTMCP_HORIZON",
        "process_instance_id": _PROCESS_INSTANCE_ID,
        **metadata,
        "confirmation_token_version": _CONFIRMATION_TOKEN_VERSION,
        "self_test": {
            "issued": True,
            "verified": verified["confirmation_verified"],
            "replay_registered": False,
            "confirmation_key_id": verified["confirmation_key_id"],
            "confirmation_key_source": verified["confirmation_key_source"],
            "issued_by_process_instance_id": verified[
                "confirmation_issued_by_process_instance_id"
            ],
            "verified_by_process_instance_id": verified[
                "confirmation_verified_by_process_instance_id"
            ],
        },
        "cross_instance_valid": None,
        "cross_instance_requirement": "MATCHING_CONFIRMATION_KEY_ID",
        "supported_rotation": {
            "previous_secret_environment_variable": (
                _PREVIOUS_SECRET_ENVIRONMENT_VARIABLE
            ),
            "previous_key_verification_enabled": metadata[
                "previous_confirmation_secret_valid"
            ],
        },
        "failure_codes": {
            "different_key": "CONFIRMATION_KEY_MISMATCH",
            "corrupted_signature": "INVALID_CONFIRMATION",
            "expired": "CONFIRMATION_EXPIRED",
            "replayed_in_process": "CONFIRMATION_REPLAYED",
        },
    }


_ORIGINAL_SAFETY_STATUS_PAYLOAD = _safety.safety_status_payload
_safety.safety_status_payload = safety_status_payload
_safety.analytics_safety_status = analytics_safety_status
_safety.issue_confirmation = issue_confirmation
_safety.verify_and_register_confirmation = verify_and_register_confirmation

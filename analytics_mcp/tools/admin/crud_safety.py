# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0

"""Security controls for protected Google Analytics Admin API mutations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Sequence

_PROPERTY_RE = re.compile(r"(?:^|/)properties/(\d+)(?:/|$)")
_STREAM_RE = re.compile(
    r"^properties/(?P<property>\d+)/dataStreams/(?P<stream>\d+)(?:/|$)"
)
_HASH_RE = re.compile(r"^[0-9a-f]{32}$")
_HASH_VERSION = 3
_DEFAULT_TTL_SECONDS = 900
_MAX_TTL_SECONDS = 3600
_DEFAULT_MAX_OPERATIONS = 10
_ABSOLUTE_MAX_OPERATIONS = 100
_CONFIRMATION_SECRET_MINIMUM_BYTES = 32


class CrudSafetyError(ValueError):
    """Structured validation or safety error."""

    def __init__(
        self,
        code: str,
        message: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})

    def as_dict(self) -> Dict[str, Any]:
        """Returns a JSON-compatible error representation."""
        return {
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


@dataclass(frozen=True)
class SafetyConfig:
    """Environment-backed mutation safety configuration."""

    mutations_enabled: bool
    allowed_account_ids: frozenset[str]
    allowed_property_ids: frozenset[str]
    allowed_data_stream_ids: frozenset[str]
    allowed_google_ads_customer_ids: frozenset[str]
    max_operations: int
    confirmation_ttl_seconds: int
    allow_create: bool
    allow_update: bool
    allow_delete: bool
    allow_archive: bool
    allow_property_update: bool
    allow_data_stream_changes: bool
    allow_key_event_changes: bool
    allow_custom_dimension_changes: bool
    allow_custom_metric_changes: bool
    allow_retention_changes: bool
    allow_attribution_changes: bool
    allow_link_changes: bool
    allow_measurement_protocol_secret_changes: bool
    allow_alpha_resources: bool


_REPLAY_LOCK = threading.Lock()
_USED_CONFIRMATIONS: Dict[str, int] = {}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise CrudSafetyError(
        "INVALID_ENVIRONMENT_VALUE",
        f"{name} must be true or false.",
        {"environment_variable": name},
    )


def _env_ids(name: str) -> frozenset[str]:
    raw = os.getenv(name, "")
    values = {item.strip() for item in raw.split(",") if item.strip()}
    invalid = sorted(item for item in values if not item.isdigit())
    if invalid:
        raise CrudSafetyError(
            "INVALID_ENVIRONMENT_VALUE",
            f"{name} must contain comma-separated numeric IDs.",
            {"invalid_values": invalid},
        )
    return frozenset(values)


def _env_int(
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise CrudSafetyError(
            "INVALID_ENVIRONMENT_VALUE",
            f"{name} must be an integer.",
            {"environment_variable": name},
        ) from exc
    if value < minimum or value > maximum:
        raise CrudSafetyError(
            "INVALID_ENVIRONMENT_VALUE",
            f"{name} must be between {minimum} and {maximum}.",
            {"environment_variable": name, "value": value},
        )
    return value


def load_safety_config() -> SafetyConfig:
    """Loads and validates the mutation safety configuration."""
    return SafetyConfig(
        mutations_enabled=_env_bool(
            "GOOGLE_ANALYTICS_ADMIN_MUTATIONS_ENABLED", False
        ),
        allowed_account_ids=_env_ids("GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS"),
        allowed_property_ids=_env_ids("GOOGLE_ANALYTICS_ALLOWED_PROPERTY_IDS"),
        allowed_data_stream_ids=_env_ids(
            "GOOGLE_ANALYTICS_ALLOWED_DATA_STREAM_IDS"
        ),
        allowed_google_ads_customer_ids=_env_ids(
            "GOOGLE_ANALYTICS_ALLOWED_GOOGLE_ADS_CUSTOMER_IDS"
        ),
        max_operations=_env_int(
            "GOOGLE_ANALYTICS_MAX_OPERATIONS_PER_REQUEST",
            _DEFAULT_MAX_OPERATIONS,
            1,
            _ABSOLUTE_MAX_OPERATIONS,
        ),
        confirmation_ttl_seconds=_env_int(
            "GOOGLE_ANALYTICS_CONFIRMATION_TTL_SECONDS",
            _DEFAULT_TTL_SECONDS,
            60,
            _MAX_TTL_SECONDS,
        ),
        allow_create=_env_bool("GOOGLE_ANALYTICS_ALLOW_CREATE", False),
        allow_update=_env_bool("GOOGLE_ANALYTICS_ALLOW_UPDATE", False),
        allow_delete=_env_bool("GOOGLE_ANALYTICS_ALLOW_DELETE", False),
        allow_archive=_env_bool("GOOGLE_ANALYTICS_ALLOW_ARCHIVE", False),
        allow_property_update=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_PROPERTY_UPDATE", False
        ),
        allow_data_stream_changes=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_DATA_STREAM_CHANGES", False
        ),
        allow_key_event_changes=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_KEY_EVENT_CHANGES", False
        ),
        allow_custom_dimension_changes=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_CUSTOM_DIMENSION_CHANGES", False
        ),
        allow_custom_metric_changes=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_CUSTOM_METRIC_CHANGES", False
        ),
        allow_retention_changes=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_RETENTION_CHANGES", False
        ),
        allow_attribution_changes=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_ATTRIBUTION_CHANGES", False
        ),
        allow_link_changes=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_LINK_CHANGES", False
        ),
        allow_measurement_protocol_secret_changes=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_MEASUREMENT_PROTOCOL_SECRET_CHANGES",
            False,
        ),
        allow_alpha_resources=_env_bool(
            "GOOGLE_ANALYTICS_ALLOW_ALPHA_RESOURCES", False
        ),
    )


def safety_status_payload(config: SafetyConfig | None = None) -> Dict[str, Any]:
    """Returns the public, secret-safe mutation safety status."""
    resolved = config or load_safety_config()
    secret = os.getenv("GOOGLE_ANALYTICS_CONFIRMATION_SECRET", "").encode(
        "utf-8"
    )
    return {
        "runtime": "PYTHON_FASTMCP_HORIZON",
        "mutations_enabled": resolved.mutations_enabled,
        "gates": {
            "create": resolved.allow_create,
            "update": resolved.allow_update,
            "delete": resolved.allow_delete,
            "archive": resolved.allow_archive,
            "property_update": resolved.allow_property_update,
            "data_stream": resolved.allow_data_stream_changes,
            "key_event": resolved.allow_key_event_changes,
            "custom_dimension": resolved.allow_custom_dimension_changes,
            "custom_metric": resolved.allow_custom_metric_changes,
            "retention": resolved.allow_retention_changes,
            "attribution": resolved.allow_attribution_changes,
            "link": resolved.allow_link_changes,
            "measurement_protocol_secret": (
                resolved.allow_measurement_protocol_secret_changes
            ),
            "alpha_resources": resolved.allow_alpha_resources,
        },
        "allowlists": {
            "account_ids": sorted(resolved.allowed_account_ids),
            "property_ids": sorted(resolved.allowed_property_ids),
            "data_stream_ids": sorted(resolved.allowed_data_stream_ids),
            "google_ads_customer_ids": sorted(
                resolved.allowed_google_ads_customer_ids
            ),
        },
        "max_operations_per_request": resolved.max_operations,
        "confirmation_ttl_seconds": resolved.confirmation_ttl_seconds,
        "confirmation_secret_configured": (
            len(secret) >= _CONFIRMATION_SECRET_MINIMUM_BYTES
        ),
        "confirmation_secret_minimum_bytes": (
            _CONFIRMATION_SECRET_MINIMUM_BYTES
        ),
        "operation_hash_version": _HASH_VERSION,
        "replay_protection": "BEST_EFFORT_PROCESS_LOCAL",
        "globally_single_use": False,
        "atomic": False,
        "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
        "admin_api_validate_only_supported": False,
        "validation_kind": "CONNECTOR_PREFLIGHT",
    }


async def analytics_safety_status() -> Dict[str, Any]:
    """Reports current mutation gates and allowlists without calling Google APIs."""
    return safety_status_payload()


def canonical_json(value: Any) -> str:
    """Serializes a value deterministically for hashing and signing."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def operation_hash(value: Any) -> str:
    """Returns a 128-bit hex digest bound to normalized operations."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[
        :32
    ]


def snapshot_hash(value: Any) -> str:
    """Returns a full SHA-256 digest for precondition snapshots."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode_canonical(value: str) -> bytes:
    if not value or "=" in value:
        raise CrudSafetyError(
            "INVALID_CONFIRMATION",
            "Confirmation contains invalid base64url encoding.",
        )
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise CrudSafetyError(
            "INVALID_CONFIRMATION",
            "Confirmation contains invalid base64url encoding.",
        ) from exc
    if _b64url_encode(decoded) != value:
        raise CrudSafetyError(
            "INVALID_CONFIRMATION",
            "Confirmation is not canonical base64url.",
        )
    return decoded


def _confirmation_secret() -> bytes:
    raw = os.getenv("GOOGLE_ANALYTICS_CONFIRMATION_SECRET", "")
    secret = raw.encode("utf-8")
    if len(secret) < _CONFIRMATION_SECRET_MINIMUM_BYTES:
        raise CrudSafetyError(
            "CONFIRMATION_SECRET_MISSING",
            "GOOGLE_ANALYTICS_CONFIRMATION_SECRET must be at least 32 bytes.",
        )
    return secret


def _purge_replay_cache(now: int) -> None:
    expired = [
        key for key, expiry in _USED_CONFIRMATIONS.items() if expiry < now
    ]
    for key in expired:
        _USED_CONFIRMATIONS.pop(key, None)


def issue_confirmation(
    normalized_payload: Mapping[str, Any],
    property_id: str,
    ttl_seconds: int,
) -> Dict[str, Any]:
    """Issues an HMAC confirmation token for validated operations."""
    digest = operation_hash(normalized_payload)
    issued_at = int(time.time())
    expires_at = issued_at + ttl_seconds
    token_payload: Dict[str, Any] = {
        "exp": expires_at,
        "hash": digest,
        "iat": issued_at,
        "nonce": _b64url_encode(secrets.token_bytes(12)),
        "pid": property_id,
        "v": 1,
        "verb": "EXECUTE",
    }
    account_id = normalized_payload.get("account_id")
    if isinstance(account_id, str) and account_id:
        token_payload["aid"] = account_id
    parent_hash = normalized_payload.get("property_parent_precondition_hash")
    if isinstance(parent_hash, str) and parent_hash:
        token_payload["pph"] = parent_hash

    encoded_payload = _b64url_encode(
        canonical_json(token_payload).encode("utf-8")
    )
    signature = _b64url_encode(
        hmac.new(
            _confirmation_secret(),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    confirmation = f"EXECUTE {digest}.{encoded_payload}.{signature}"
    return {
        "operation_hash": digest,
        "operation_hash_version": _HASH_VERSION,
        "required_confirmation": confirmation,
        "confirmation_expires_at_epoch": expires_at,
        "validation_receipt": {
            "expires_at_epoch": expires_at,
            "cross_instance_valid": True,
            "replay_protection": "BEST_EFFORT_PROCESS_LOCAL",
            "globally_single_use": False,
        },
    }


def verify_and_register_confirmation(
    confirmation: str,
    normalized_payload: Mapping[str, Any],
    property_id: str,
) -> Dict[str, Any]:
    """Verifies and registers a confirmation before an API call."""
    try:
        verb, token = confirmation.split(" ", 1)
        digest, encoded_payload, signature = token.split(".", 2)
    except ValueError as exc:
        raise CrudSafetyError(
            "INVALID_CONFIRMATION",
            "Confirmation must use 'EXECUTE <hash>.<payload>.<signature>'.",
        ) from exc
    if verb != "EXECUTE" or not _HASH_RE.fullmatch(digest):
        raise CrudSafetyError(
            "INVALID_CONFIRMATION", "Confirmation prefix or hash is invalid."
        )

    expected_signature = _b64url_encode(
        hmac.new(
            _confirmation_secret(),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    if not hmac.compare_digest(signature, expected_signature):
        raise CrudSafetyError(
            "INVALID_CONFIRMATION", "Confirmation signature is invalid."
        )

    decoded = _b64url_decode_canonical(encoded_payload)
    try:
        payload = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CrudSafetyError(
            "INVALID_CONFIRMATION", "Confirmation payload is invalid."
        ) from exc

    expected_hash = operation_hash(normalized_payload)
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
        raise CrudSafetyError(
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
        raise CrudSafetyError(
            "PROPERTY_PARENT_ACCOUNT_CHANGED",
            "The property parent account changed after validation.",
        )

    if digest != expected_hash or observed != expected:
        raise CrudSafetyError(
            "CONFIRMATION_MISMATCH",
            "Confirmation does not match the normalized operation payload.",
            {"expected": expected, "observed": observed},
        )
    if not isinstance(payload.get("exp"), int) or payload["exp"] < now:
        raise CrudSafetyError(
            "CONFIRMATION_EXPIRED",
            "Confirmation has expired and the operation must be revalidated.",
        )
    if not isinstance(payload.get("iat"), int) or payload["iat"] > now + 60:
        raise CrudSafetyError(
            "INVALID_CONFIRMATION", "Confirmation issue time is invalid."
        )
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise CrudSafetyError(
            "INVALID_CONFIRMATION", "Confirmation nonce is missing."
        )

    fingerprint = hashlib.sha256(confirmation.encode("utf-8")).hexdigest()[:16]
    with _REPLAY_LOCK:
        _purge_replay_cache(now)
        if fingerprint in _USED_CONFIRMATIONS:
            raise CrudSafetyError(
                "CONFIRMATION_REPLAYED",
                "Confirmation was already registered by this process.",
            )
        _USED_CONFIRMATIONS[fingerprint] = payload["exp"]

    return {
        "confirmation_verified": True,
        "confirmation_registered_before_api_call": True,
        "confirmation_token_fingerprint": fingerprint,
        "operation_hash": expected_hash,
        "operation_hash_version": _HASH_VERSION,
    }


def extract_property_ids(value: Any) -> frozenset[str]:
    """Recursively extracts property IDs from payload values."""
    found: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, str):
            found.update(_PROPERTY_RE.findall(node))
        elif isinstance(node, Mapping):
            for key, item in node.items():
                visit(key)
                visit(item)
        elif isinstance(node, Sequence) and not isinstance(
            node, (str, bytes, bytearray)
        ):
            for item in node:
                visit(item)

    visit(value)
    return frozenset(found)


def validate_account_scope(account_id: str, config: SafetyConfig) -> None:
    """Enforces the Analytics account mutation allowlist."""
    if not config.allowed_account_ids:
        raise CrudSafetyError(
            "ACCOUNT_ALLOWLIST_EMPTY",
            "GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS is not configured.",
        )
    if account_id not in config.allowed_account_ids:
        raise CrudSafetyError(
            "ACCOUNT_NOT_ALLOWED",
            f"Account {account_id} is not in the mutation allowlist.",
        )


def validate_google_ads_customer_scope(
    customer_id: str,
    config: SafetyConfig,
) -> None:
    """Enforces the Google Ads customer allowlist for link mutations."""
    if not customer_id or not customer_id.isdigit():
        raise CrudSafetyError(
            "INVALID_GOOGLE_ADS_CUSTOMER_ID",
            "Google Ads customer_id must be numeric.",
        )
    if not config.allowed_google_ads_customer_ids:
        raise CrudSafetyError(
            "GOOGLE_ADS_CUSTOMER_ALLOWLIST_EMPTY",
            "GOOGLE_ANALYTICS_ALLOWED_GOOGLE_ADS_CUSTOMER_IDS is not configured.",
        )
    if customer_id not in config.allowed_google_ads_customer_ids:
        raise CrudSafetyError(
            "GOOGLE_ADS_CUSTOMER_NOT_ALLOWED",
            f"Google Ads customer {customer_id} is not in the mutation allowlist.",
        )


def validate_property_scope(
    property_id: str,
    payload: Any,
    config: SafetyConfig,
) -> None:
    """Enforces property allowlist and rejects cross-property references."""
    if not property_id.isdigit():
        raise CrudSafetyError(
            "INVALID_PROPERTY_ID", "property_id must be numeric."
        )
    if not config.allowed_property_ids:
        raise CrudSafetyError(
            "PROPERTY_ALLOWLIST_EMPTY",
            "GOOGLE_ANALYTICS_ALLOWED_PROPERTY_IDS is not configured.",
        )
    if property_id not in config.allowed_property_ids:
        raise CrudSafetyError(
            "PROPERTY_NOT_ALLOWED",
            f"Property {property_id} is not in the mutation allowlist.",
        )
    referenced = extract_property_ids(payload)
    foreign = sorted(item for item in referenced if item != property_id)
    if foreign:
        raise CrudSafetyError(
            "CROSS_PROPERTY_REFERENCE",
            "Payload references a different Analytics property.",
            {"foreign_property_ids": foreign},
        )


def validate_stream_scope(
    parent_or_name: str,
    property_id: str,
    config: SafetyConfig,
) -> None:
    """Enforces the optional data-stream allowlist."""
    match = _STREAM_RE.match(parent_or_name)
    if not match:
        raise CrudSafetyError(
            "INVALID_DATA_STREAM_RESOURCE_NAME",
            "Expected properties/<id>/dataStreams/<stream_id>.",
        )
    if match.group("property") != property_id:
        raise CrudSafetyError(
            "CROSS_PROPERTY_REFERENCE",
            "Data stream belongs to a different Analytics property.",
        )
    stream_id = match.group("stream")
    if config.allowed_data_stream_ids and stream_id not in (
        config.allowed_data_stream_ids
    ):
        raise CrudSafetyError(
            "DATA_STREAM_NOT_ALLOWED",
            f"Data stream {stream_id} is not in the mutation allowlist.",
        )


def enforce_action_gates(
    resource: str,
    action: str,
    api_channel: str,
    risk_gate: str | None,
    config: SafetyConfig,
) -> None:
    """Enforces independent environment gates for risky mutations."""
    if action in {"get", "list"}:
        return
    if not config.mutations_enabled:
        raise CrudSafetyError(
            "MUTATIONS_DISABLED",
            "Google Analytics Admin mutations are disabled.",
        )
    if action == "create" and not config.allow_create:
        raise CrudSafetyError(
            "CREATE_DISABLED",
            "Create operations are disabled by GOOGLE_ANALYTICS_ALLOW_CREATE.",
        )
    if action == "update" and not config.allow_update:
        raise CrudSafetyError(
            "UPDATE_DISABLED",
            "Update operations are disabled by GOOGLE_ANALYTICS_ALLOW_UPDATE.",
        )
    if action == "delete" and not config.allow_delete:
        raise CrudSafetyError(
            "DELETE_DISABLED",
            "Delete operations are disabled by GOOGLE_ANALYTICS_ALLOW_DELETE.",
        )
    if action == "archive" and not config.allow_archive:
        raise CrudSafetyError(
            "ARCHIVE_DISABLED",
            "Archive operations are disabled by GOOGLE_ANALYTICS_ALLOW_ARCHIVE.",
        )
    if api_channel == "alpha" and not config.allow_alpha_resources:
        raise CrudSafetyError(
            "ALPHA_RESOURCES_DISABLED",
            "Alpha resources are disabled by configuration.",
        )

    gate_values = {
        "property": config.allow_property_update,
        "data_stream": config.allow_data_stream_changes,
        "key_event": config.allow_key_event_changes,
        "custom_dimension": config.allow_custom_dimension_changes,
        "custom_metric": config.allow_custom_metric_changes,
        "retention": config.allow_retention_changes,
        "attribution": config.allow_attribution_changes,
        "link": config.allow_link_changes,
        "measurement_protocol_secret": (
            config.allow_measurement_protocol_secret_changes
        ),
    }
    if risk_gate and not gate_values.get(risk_gate, True):
        raise CrudSafetyError(
            "RESOURCE_GATE_DISABLED",
            f"Mutations for {resource} are disabled by configuration.",
            {"risk_gate": risk_gate},
        )


def validate_operation_count(
    operations: Iterable[Mapping[str, Any]], config: SafetyConfig
) -> list[Mapping[str, Any]]:
    """Materializes operations and enforces configured limits."""
    materialized = list(operations)
    if not materialized:
        raise CrudSafetyError(
            "EMPTY_OPERATION_BATCH", "At least one operation is required."
        )
    if len(materialized) > config.max_operations:
        raise CrudSafetyError(
            "TOO_MANY_OPERATIONS",
            f"At most {config.max_operations} operations are allowed.",
            {"operation_count": len(materialized)},
        )
    return materialized

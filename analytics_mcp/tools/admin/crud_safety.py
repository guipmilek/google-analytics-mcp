# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0

"""Scope and validation controls for direct Analytics Admin CRUD."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Sequence

_PROPERTY_RE = re.compile(r"(?:^|/)properties/(\d+)(?:/|$)")
_STREAM_RE = re.compile(
    r"^properties/(?P<property>\d+)/dataStreams/(?P<stream>\d+)(?:/|$)"
)
_HASH_VERSION = 3
_DEFAULT_MAX_OPERATIONS = 10
_ABSOLUTE_MAX_OPERATIONS = 100
CRUD_CONTRACT_VERSION = "direct-crud-v1"


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
    """Environment-backed direct CRUD scope."""

    allowed_account_ids: frozenset[str]
    allowed_property_ids: frozenset[str]
    allowed_data_stream_ids: frozenset[str]
    allowed_google_ads_customer_ids: frozenset[str]
    max_operations: int


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
    """Loads direct CRUD scope and ignores legacy approval-gate variables."""
    return SafetyConfig(
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
    )


def safety_status_payload(config: SafetyConfig | None = None) -> Dict[str, Any]:
    """Returns the public direct CRUD contract and non-secret scope."""
    resolved = config or load_safety_config()
    return {
        "contract_version": CRUD_CONTRACT_VERSION,
        "runtime": "PYTHON_FASTMCP_HORIZON",
        "write_mode": "DIRECT",
        "dry_run_supported": True,
        "approval_workflow": False,
        "allowlists": {
            "account_ids": sorted(resolved.allowed_account_ids),
            "property_ids": sorted(resolved.allowed_property_ids),
            "data_stream_ids": sorted(resolved.allowed_data_stream_ids),
            "google_ads_customer_ids": sorted(
                resolved.allowed_google_ads_customer_ids
            ),
        },
        "max_operations_per_request": resolved.max_operations,
        "operation_hash_version": _HASH_VERSION,
        "atomic": False,
        "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
        "admin_api_validate_only_supported": False,
    }


async def analytics_crud_status() -> Dict[str, Any]:
    """Reports the direct CRUD contract without calling Google APIs."""
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

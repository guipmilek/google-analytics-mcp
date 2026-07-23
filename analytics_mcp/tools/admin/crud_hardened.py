# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Direct public facade for the Analytics Admin CRUD engine."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Mapping, Sequence

from google.analytics import admin_v1beta
from google.api_core import exceptions as google_exceptions

from analytics_mcp.tools.admin import crud as _crud
from analytics_mcp.tools.admin.crud_registry import get_resource_spec
from analytics_mcp.tools.admin.crud_safety import (
    CRUD_CONTRACT_VERSION,
    CrudSafetyError,
    analytics_crud_status,
    load_safety_config,
    operation_hash,
    snapshot_hash,
    validate_account_scope,
    validate_google_ads_customer_scope,
    validate_operation_count,
    validate_property_scope,
    validate_stream_scope,
)
from analytics_mcp.tools.client import create_admin_api_client
from analytics_mcp.tools.utils import construct_property_rn, proto_to_dict

analytics_get_mutation_schema = _crud.analytics_get_mutation_schema
analytics_get_resource = _crud.analytics_get_resource
analytics_list_mutable_resources = _crud.analytics_list_mutable_resources
analytics_list_resources = _crud.analytics_list_resources


def _safe_execute_one_sync(operation: Mapping[str, Any]) -> Dict[str, Any]:
    """Execute one mutation and report post-read failures separately."""

    spec = get_resource_spec(str(operation["resource"]))
    action = str(operation["action"])
    request = _crud._build_request(
        spec,
        action,
        parent=operation.get("parent"),
        resource_name=operation.get("resource_name"),
        data=operation.get("data"),
        update_mask=operation.get("update_mask"),
    )
    response = _crud._invoke(spec, action, request, write=True)
    response_dict = None
    if response is not None and hasattr(type(response), "to_dict"):
        response_dict = _crud.proto_to_dict(response)

    observed = None
    observed_name = operation.get("resource_name")
    if action == "create" and response_dict:
        observed_name = response_dict.get("name")

    verification_status = "NOT_APPLICABLE"
    verification_error = None
    if observed_name:
        try:
            observed = _crud._get_sync(spec, str(observed_name))
            verification_status = "VERIFIED"
        except google_exceptions.NotFound:
            if action in {"archive", "delete"}:
                verification_status = "VERIFIED"
            else:
                verification_status = "FAILED"
                verification_error = {
                    "error_type": "NotFound",
                    "message": "Resource was not readable after mutation.",
                }
        except CrudSafetyError as exc:
            if (
                action in {"archive", "delete"}
                and exc.code == "RESOURCE_NOT_FOUND"
            ):
                verification_status = "VERIFIED"
            else:
                verification_status = "FAILED"
                verification_error = exc.as_dict()
        except Exception as exc:
            verification_status = "FAILED"
            verification_error = {
                "error_type": type(exc).__name__,
                "message": str(exc),
            }

    return {
        "action": action,
        "resource": spec.name,
        "resource_name": observed_name,
        "response": response_dict,
        "post_execution_observation": observed,
        "post_execution_verification_status": verification_status,
        "post_execution_verification_error": verification_error,
    }


# Keep the shared engine's executor aligned with the Horizon facade.
_crud._execute_one_sync = _safe_execute_one_sync


def _validate_data_stream_mutation_scope(
    property_id: int | str,
    operations: List[Dict[str, Any]],
) -> None:
    """Apply the optional stream allowlist to existing DataStream mutations."""

    _, property_num = _crud._property_parts(property_id)
    config = load_safety_config()
    for operation in operations:
        if operation.get("resource") != "DataStream":
            continue
        if str(operation.get("action", "")).lower() == "create":
            continue
        resource_name = operation.get("resource_name")
        if not isinstance(resource_name, str):
            raise CrudSafetyError(
                "RESOURCE_NAME_REQUIRED",
                "resource_name is required for DataStream mutations.",
            )
        validate_stream_scope(resource_name, property_num, config)


def _read_property_sync(property_id: str) -> Dict[str, Any]:
    request = admin_v1beta.GetPropertyRequest(
        name=construct_property_rn(property_id)
    )
    response = create_admin_api_client().get_property(request=request)
    return proto_to_dict(response)


def _account_context_sync(property_id: str, config) -> Dict[str, str]:
    """Read and validate the parent Analytics account for the property."""

    property_data = _read_property_sync(property_id)
    parent = str(property_data.get("parent", ""))
    if not parent.startswith("accounts/"):
        raise CrudSafetyError(
            "INVALID_PROPERTY_PARENT",
            "The Analytics property did not expose a valid parent account.",
            {"parent": parent},
        )
    account_id = parent.split("/", 1)[1]
    if not account_id.isdigit():
        raise CrudSafetyError(
            "INVALID_PROPERTY_PARENT",
            "The Analytics property parent account is not numeric.",
            {"parent": parent},
        )
    validate_account_scope(account_id, config)
    parent_snapshot = {
        "property_name": property_data.get("name"),
        "parent": parent,
    }
    return {
        "account_id": account_id,
        "property_parent": parent,
        "property_parent_precondition_hash": snapshot_hash(parent_snapshot),
    }


def _validate_google_ads_link_operations_sync(
    operations: Sequence[Mapping[str, Any]],
    config,
) -> List[Dict[str, Any]]:
    """Bind Google Ads link operations to an authorized customer ID."""

    normalized: List[Dict[str, Any]] = []
    link_spec = get_resource_spec("GoogleAdsLink")
    for item in operations:
        operation = dict(item)
        if operation.get("resource") != "GoogleAdsLink":
            normalized.append(operation)
            continue

        action = str(operation.get("action"))
        if action == "create":
            customer_id = str(operation.get("data", {}).get("customer_id", ""))
        else:
            resource_name = operation.get("resource_name")
            if not isinstance(resource_name, str) or not resource_name:
                raise CrudSafetyError(
                    "RESOURCE_NAME_REQUIRED",
                    "resource_name is required for GoogleAdsLink mutations.",
                )
            if operation.get("no_op_reason") == "ALREADY_ABSENT":
                normalized.append(operation)
                continue
            current = _crud._get_sync(link_spec, resource_name)
            customer_id = str(current.get("customer_id", ""))

        validate_google_ads_customer_scope(customer_id, config)
        operation["google_ads_customer_id"] = customer_id
        normalized.append(operation)
    return normalized


def _operation_payload(
    property_num: str,
    account_context: Mapping[str, str],
    normalized: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    return {
        "contract_version": CRUD_CONTRACT_VERSION,
        "property_id": property_num,
        "account_id": account_context["account_id"],
        "property_parent_precondition_hash": account_context[
            "property_parent_precondition_hash"
        ],
        "operations": list(normalized),
        "atomic": False,
        "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
    }


def _operation_scope(operations: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    return _crud._operation_scope(operations)


def _known_rejection(exc: Exception) -> bool:
    return isinstance(
        exc,
        (
            google_exceptions.InvalidArgument,
            google_exceptions.PermissionDenied,
            google_exceptions.NotFound,
            google_exceptions.AlreadyExists,
            google_exceptions.FailedPrecondition,
            google_exceptions.Unauthenticated,
            CrudSafetyError,
        ),
    )


def _add_verification_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    """Report post-read warnings without changing mutation dispatch facts."""

    if result.get("mode") != "EXECUTE":
        return result
    if result.get("execution_status") != "SUCCEEDED":
        return result

    failures = [
        item
        for item in result.get("results", [])
        if item.get("post_execution_verification_status") == "FAILED"
    ]
    result["execution_status"] = (
        "SUCCEEDED" if not failures else "SUCCEEDED_WITH_VERIFICATION_WARNINGS"
    )
    result["verification"] = {
        "post_execution_reads_performed": result.get(
            "execution_attempted", False
        ),
        "all_requested_resources_verified": not failures,
        "verification_failure_count": len(failures),
        "claims_limited_to_requested_resources": True,
    }
    return result


async def analytics_batch_operations(
    property_id: int | str,
    operations: List[Dict[str, Any]],
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Validate and directly execute a non-atomic Admin API batch."""

    _validate_data_stream_mutation_scope(property_id, operations)
    _, property_num = _crud._property_parts(property_id)
    config = load_safety_config()
    materialized = validate_operation_count(operations, config)
    validate_property_scope(property_num, materialized, config)

    account_context = await asyncio.to_thread(
        _account_context_sync, property_num, config
    )
    normalized = await asyncio.to_thread(
        _crud._normalize_batch_sync,
        property_num,
        materialized,
        config,
    )
    normalized = await asyncio.to_thread(
        _validate_google_ads_link_operations_sync,
        normalized,
        config,
    )
    payload = _operation_payload(property_num, account_context, normalized)
    digest = operation_hash(payload)

    if dry_run:
        return {
            "contract_version": CRUD_CONTRACT_VERSION,
            "account_id": account_context["account_id"],
            "property_id": property_num,
            "mode": "DRY_RUN",
            "execution_attempted": False,
            "executed": False,
            "execution_status": "NOT_EXECUTED",
            "operation_count": len(normalized),
            "normalized_operations": normalized,
            "operation_scope": _operation_scope(normalized),
            "operation_hash": digest,
            "verification": {
                "sdk_request_objects_built": True,
                "precondition_reads_performed": True,
                "property_parent_account_verified": True,
                "admin_api_mutation_sent": False,
                "post_mutation_read_performed": False,
            },
        }

    results: List[Dict[str, Any]] = []
    mutation_attempts = 0
    for index, operation in enumerate(normalized):
        if operation.get("no_op_reason"):
            results.append(
                {
                    "operation_index": index,
                    "action": operation["action"],
                    "resource": operation["resource"],
                    "resource_name": operation.get("resource_name"),
                    "execution_status": "SUCCEEDED",
                    "outcome": operation["no_op_reason"],
                    "post_execution_verification_status": "VERIFIED",
                }
            )
            continue

        mutation_attempts += 1
        try:
            item = await asyncio.to_thread(_safe_execute_one_sync, operation)
            item["operation_index"] = index
            item["execution_status"] = "SUCCEEDED"
            item["outcome"] = "MUTATED"
            results.append(item)
        except Exception as exc:
            rejected = _known_rejection(exc)
            error = {
                "operation_index": index,
                "action": operation["action"],
                "resource": operation["resource"],
                "resource_name": operation.get("resource_name"),
                "error_type": type(exc).__name__,
                "message": str(exc),
                "execution_state": "NOT_EXECUTED" if rejected else "UNKNOWN",
                "execution_may_have_completed": not rejected,
                "automatic_retry_safe": False,
            }
            completed = sum(
                item.get("execution_status") == "SUCCEEDED" for item in results
            )
            return {
                "contract_version": CRUD_CONTRACT_VERSION,
                "account_id": account_context["account_id"],
                "property_id": property_num,
                "mode": "EXECUTE",
                "execution_attempted": True,
                "executed": False if not results and rejected else None,
                "execution_status": (
                    "FAILED"
                    if not results and rejected
                    else "PARTIAL_OR_UNKNOWN"
                ),
                "atomic": False,
                "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
                "operation_count": len(normalized),
                "operations_attempted": len(results) + 1,
                "operations_completed": completed,
                "operations_not_attempted": len(normalized) - len(results) - 1,
                "results": results,
                "error": error,
                "operation_scope": _operation_scope(normalized),
                "operation_hash": digest,
            }

    result = {
        "contract_version": CRUD_CONTRACT_VERSION,
        "account_id": account_context["account_id"],
        "property_id": property_num,
        "mode": "EXECUTE",
        "execution_attempted": mutation_attempts > 0,
        "executed": mutation_attempts > 0,
        "execution_status": "SUCCEEDED",
        "atomic": False,
        "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
        "operation_count": len(normalized),
        "operations_attempted": len(normalized),
        "operations_completed": len(normalized),
        "operations_not_attempted": 0,
        "results": results,
        "operation_scope": _operation_scope(normalized),
        "operation_hash": digest,
    }
    return _add_verification_summary(result)


async def analytics_create_resource(
    property_id: int | str,
    resource: str,
    data: Dict[str, Any],
    parent: str | None = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Create one Analytics Admin resource directly."""

    return await analytics_batch_operations(
        property_id,
        [
            {
                "action": "create",
                "resource": resource,
                "parent": parent,
                "data": data,
            }
        ],
        dry_run,
    )


async def analytics_update_resource(
    property_id: int | str,
    resource: str,
    resource_name: str,
    data: Dict[str, Any],
    update_mask: List[str],
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Update one Analytics Admin resource directly."""

    return await analytics_batch_operations(
        property_id,
        [
            {
                "action": "update",
                "resource": resource,
                "resource_name": resource_name,
                "data": data,
                "update_mask": update_mask,
            }
        ],
        dry_run,
    )


async def analytics_archive_resource(
    property_id: int | str,
    resource: str,
    resource_name: str,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Archive one Analytics Admin resource directly."""

    return await analytics_batch_operations(
        property_id,
        [
            {
                "action": "archive",
                "resource": resource,
                "resource_name": resource_name,
            }
        ],
        dry_run,
    )


async def analytics_delete_resource(
    property_id: int | str,
    resource: str,
    resource_name: str,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Delete one resource directly; an absent resource is a successful no-op."""

    return await analytics_batch_operations(
        property_id,
        [
            {
                "action": "delete",
                "resource": resource,
                "resource_name": resource_name,
            }
        ],
        dry_run,
    )

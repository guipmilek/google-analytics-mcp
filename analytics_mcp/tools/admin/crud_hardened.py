# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0

"""Hardened public facade for the Analytics Admin CRUD engine."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Sequence

from google.analytics import admin_v1beta
from google.api_core import exceptions as google_exceptions

from analytics_mcp.tools.admin.crud_safety import (
    CrudSafetyError,
    analytics_safety_status,
    issue_confirmation,
    load_safety_config,
    snapshot_hash,
    validate_account_scope,
    validate_google_ads_customer_scope,
    validate_operation_count,
    validate_property_scope,
    validate_stream_scope,
    verify_and_register_confirmation,
)
from analytics_mcp.tools.client import create_admin_api_client
from analytics_mcp.tools.utils import construct_property_rn, proto_to_dict


from analytics_mcp.tools.admin import crud as _crud  # noqa: E402
from analytics_mcp.tools.admin.crud_registry import (
    get_resource_spec,
)  # noqa: E402

analytics_get_mutation_schema = _crud.analytics_get_mutation_schema
analytics_get_resource = _crud.analytics_get_resource
analytics_list_mutable_resources = _crud.analytics_list_mutable_resources
analytics_list_resources = _crud.analytics_list_resources


def _safe_execute_one_sync(operation: Mapping[str, Any]) -> Dict[str, Any]:
    """Executes one mutation without conflating post-read failure with dispatch."""
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


_crud._execute_one_sync = _safe_execute_one_sync


def _validate_data_stream_mutation_scope(
    property_id: int | str,
    operations: List[Dict[str, Any]],
) -> None:
    """Applies the stream allowlist to existing DataStream mutations."""
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
    """Reads and validates the parent Analytics account for the property."""
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
    """Binds Google Ads link operations to an authorized customer ID."""
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
            current = _crud._get_sync(link_spec, resource_name)
            customer_id = str(current.get("customer_id", ""))

        validate_google_ads_customer_scope(customer_id, config)
        operation["google_ads_customer_id"] = customer_id
        normalized.append(operation)
    return normalized


def _signed_payload(
    property_num: str,
    account_context: Mapping[str, str],
    normalized: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    return {
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


def _iso_time(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _validation_response(
    property_num: str,
    account_context: Mapping[str, str],
    normalized: List[Dict[str, Any]],
    config,
) -> Dict[str, Any]:
    signed_payload = _signed_payload(property_num, account_context, normalized)
    receipt = issue_confirmation(
        signed_payload,
        property_num,
        config.confirmation_ttl_seconds,
    )
    expires_epoch = receipt.pop("confirmation_expires_at_epoch")
    response = {
        "account_id": account_context["account_id"],
        "property_id": property_num,
        "mode": "VALIDATE_ONLY",
        "validation_kind": "CONNECTOR_PREFLIGHT",
        "admin_api_validate_only_supported": False,
        "validation_status": "PASSED",
        "validated": True,
        "validated_in_current_call": True,
        "execution_attempted": False,
        "executed": False,
        "execution_status": "NOT_EXECUTED",
        "operation_count": len(normalized),
        "normalized_operations": normalized,
        "operation_scope": _operation_scope(normalized),
        "confirmation_expires_at": _iso_time(expires_epoch),
        "verification": {
            "sdk_request_objects_built": True,
            "precondition_reads_performed": True,
            "property_parent_account_verified": True,
            "google_ads_customer_allowlist_verified": any(
                item.get("resource") == "GoogleAdsLink" for item in normalized
            ),
            "admin_api_mutation_sent": False,
            "post_mutation_read_performed": False,
        },
    }
    response.update(receipt)
    receipt_data = response.get("validation_receipt", {})
    receipt_data["expires_at"] = response["confirmation_expires_at"]
    receipt_data.pop("expires_at_epoch", None)
    return response


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
    """Reports post-read warnings without changing mutation dispatch facts."""
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
        "post_execution_reads_performed": True,
        "all_requested_resources_verified": not failures,
        "verification_failure_count": len(failures),
        "claims_limited_to_requested_resources": True,
    }
    return result


async def analytics_batch_operations(
    property_id: int | str,
    operations: List[Dict[str, Any]],
    validate_only: bool = True,
    confirmation: str | None = None,
) -> Dict[str, Any]:
    """Validates or executes a hardened, non-atomic Admin API batch."""
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

    if validate_only:
        return _validation_response(
            property_num,
            account_context,
            normalized,
            config,
        )

    if not confirmation:
        raise CrudSafetyError(
            "CONFIRMATION_REQUIRED",
            "A signed confirmation from a prior validation is required.",
        )

    signed_payload = _signed_payload(property_num, account_context, normalized)
    confirmation_info = verify_and_register_confirmation(
        confirmation,
        signed_payload,
        property_num,
    )

    results: List[Dict[str, Any]] = []
    attempted = 0
    for index, operation in enumerate(normalized):
        attempted += 1
        try:
            result = await asyncio.to_thread(_safe_execute_one_sync, operation)
            result["operation_index"] = index
            result["execution_status"] = "SUCCEEDED"
            results.append(result)
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
            return {
                "account_id": account_context["account_id"],
                "property_id": property_num,
                "mode": "EXECUTE",
                "validation_status": "PRIOR_VALIDATION_VERIFIED",
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
                "operations_attempted": attempted,
                "operations_completed": len(results),
                "operations_not_attempted": len(normalized) - attempted,
                "results": results,
                "error": error,
                "operation_scope": _operation_scope(normalized),
                **confirmation_info,
            }

    result = {
        "account_id": account_context["account_id"],
        "property_id": property_num,
        "mode": "EXECUTE",
        "validation_status": "PRIOR_VALIDATION_VERIFIED",
        "execution_attempted": True,
        "executed": True,
        "execution_status": "SUCCEEDED",
        "atomic": False,
        "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
        "operation_count": len(normalized),
        "operations_attempted": len(normalized),
        "operations_completed": len(normalized),
        "operations_not_attempted": 0,
        "results": results,
        "operation_scope": _operation_scope(normalized),
        "verification": {
            "post_execution_reads_performed": True,
            "claims_limited_to_requested_resources": True,
        },
        **confirmation_info,
    }
    return _add_verification_summary(result)


async def analytics_create_resource(
    property_id: int | str,
    resource: str,
    data: Dict[str, Any],
    parent: str | None = None,
    validate_only: bool = True,
    confirmation: str | None = None,
) -> Dict[str, Any]:
    """Creates one resource through the hardened CRUD facade."""
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
        validate_only,
        confirmation,
    )


async def analytics_update_resource(
    property_id: int | str,
    resource: str,
    resource_name: str,
    data: Dict[str, Any],
    update_mask: List[str],
    validate_only: bool = True,
    confirmation: str | None = None,
) -> Dict[str, Any]:
    """Updates one resource through the hardened CRUD facade."""
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
        validate_only,
        confirmation,
    )


async def analytics_archive_resource(
    property_id: int | str,
    resource: str,
    resource_name: str,
    validate_only: bool = True,
    confirmation: str | None = None,
) -> Dict[str, Any]:
    """Archives one resource through the hardened CRUD facade."""
    return await analytics_batch_operations(
        property_id,
        [
            {
                "action": "archive",
                "resource": resource,
                "resource_name": resource_name,
            }
        ],
        validate_only,
        confirmation,
    )


async def analytics_delete_resource(
    property_id: int | str,
    resource: str,
    resource_name: str,
    validate_only: bool = True,
    confirmation: str | None = None,
) -> Dict[str, Any]:
    """Deletes one resource through the hardened CRUD facade."""
    return await analytics_batch_operations(
        property_id,
        [
            {
                "action": "delete",
                "resource": resource,
                "resource_name": resource_name,
            }
        ],
        validate_only,
        confirmation,
    )

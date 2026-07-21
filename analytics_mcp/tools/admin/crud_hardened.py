# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0

"""Hardened public facade for the Analytics Admin CRUD engine."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from google.api_core import exceptions as google_exceptions

from analytics_mcp.tools.admin import crud as _crud
from analytics_mcp.tools.admin.crud_registry import get_resource_spec
from analytics_mcp.tools.admin.crud_safety import (
    CrudSafetyError,
    load_safety_config,
    validate_stream_scope,
)

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


# The core batch resolves this global when it starts each operation. Replacing it
# here preserves the public CRUD API while separating API dispatch from the
# best-effort read that follows it.
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
    result = await _crud.analytics_batch_operations(
        property_id=property_id,
        operations=operations,
        validate_only=validate_only,
        confirmation=confirmation,
    )
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

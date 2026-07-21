# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0

"""Protected generic CRUD tools for the Google Analytics Admin API."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Sequence

from google.analytics import admin_v1alpha, admin_v1beta
from google.api_core import exceptions as google_exceptions
from google.protobuf.field_mask_pb2 import FieldMask

from analytics_mcp.tools.admin.crud_registry import (
    ResourceSpec,
    get_resource_spec,
    list_resource_specs,
)
from analytics_mcp.tools.admin.crud_safety import (
    CrudSafetyError,
    enforce_action_gates,
    issue_confirmation,
    load_safety_config,
    snapshot_hash,
    validate_operation_count,
    validate_property_scope,
    validate_stream_scope,
    verify_and_register_confirmation,
)
from analytics_mcp.tools.client import (
    create_admin_alpha_api_client,
    create_admin_api_client,
)
from analytics_mcp.tools.utils import construct_property_rn, proto_to_dict


_MUTATING_ACTIONS = {"create", "update", "archive", "delete"}


def _property_parts(property_id: int | str) -> tuple[str, str]:
    property_name = construct_property_rn(property_id)
    return property_name, property_name.rsplit("/", 1)[1]


def _module_for(spec: ResourceSpec):
    if spec.api_channel == "alpha":
        return admin_v1alpha
    return admin_v1beta


def _client_for(spec: ResourceSpec, write: bool = False):
    if spec.api_channel == "alpha":
        return create_admin_alpha_api_client(write=write)
    return create_admin_api_client(write=write)


def _canonical_field_name(spec: ResourceSpec, value: str) -> str:
    reverse_aliases = {
        alias: canonical for canonical, alias in spec.aliases.items()
    }
    if value in spec.aliases:
        return value
    return reverse_aliases.get(value, value)


def _sdk_field_name(spec: ResourceSpec, value: str) -> str:
    return spec.aliases.get(value, value)


def _normalize_data(
    spec: ResourceSpec,
    action: str,
    data: Mapping[str, Any] | None,
) -> Dict[str, Any]:
    raw = dict(data or {})
    field_map = spec.field_map
    normalized: Dict[str, Any] = {}

    for input_name, value in raw.items():
        canonical = _canonical_field_name(spec, input_name)
        if canonical in normalized:
            raise CrudSafetyError(
                "AMBIGUOUS_FIELD_ALIAS",
                f"Field '{canonical}' was supplied more than once.",
            )
        field = field_map.get(canonical)
        if field is None:
            raise CrudSafetyError(
                "UNKNOWN_FIELD",
                f"Field '{input_name}' is not supported for {spec.name}.",
            )
        if field.output_only:
            raise CrudSafetyError(
                "OUTPUT_ONLY_FIELD",
                f"Field '{canonical}' is output-only.",
            )
        if action == "create" and not field.writable_on_create:
            raise CrudSafetyError(
                "FIELD_NOT_WRITABLE_ON_CREATE",
                f"Field '{canonical}' cannot be supplied during create.",
            )
        if action == "update" and not field.writable_on_update:
            code = "IMMUTABLE_FIELD" if field.immutable else "FIELD_NOT_WRITABLE"
            raise CrudSafetyError(
                code,
                f"Field '{canonical}' cannot be updated.",
            )
        if field.enum_values and isinstance(value, str):
            if value not in field.enum_values:
                raise CrudSafetyError(
                    "INVALID_ENUM_VALUE",
                    f"Invalid value '{value}' for field '{canonical}'.",
                    {"allowed_values": list(field.enum_values)},
                )
        normalized[canonical] = value

    if action == "create":
        missing = sorted(
            item.name
            for item in spec.fields
            if item.required_on_create and item.name not in normalized
        )
        if missing:
            raise CrudSafetyError(
                "MISSING_REQUIRED_FIELDS",
                "Required create fields are missing.",
                {"fields": missing},
            )
    return normalized


def _normalize_update_mask(
    spec: ResourceSpec,
    data: Mapping[str, Any],
    update_mask: Sequence[str] | None,
) -> List[str]:
    if not update_mask:
        raise CrudSafetyError(
            "UPDATE_MASK_REQUIRED", "update_mask is required for updates."
        )
    field_map = spec.field_map
    normalized: List[str] = []
    for path in update_mask:
        if not isinstance(path, str) or not path.strip():
            raise CrudSafetyError(
                "INVALID_UPDATE_MASK", "update_mask paths must be strings."
            )
        parts = path.strip().split(".")
        canonical_top = _canonical_field_name(spec, parts[0])
        field = field_map.get(canonical_top)
        if field is None:
            raise CrudSafetyError(
                "UNKNOWN_UPDATE_MASK_FIELD",
                f"Unknown update_mask field '{parts[0]}'.",
            )
        if field.output_only or not field.writable_on_update:
            raise CrudSafetyError(
                "INVALID_UPDATE_MASK_FIELD",
                f"Field '{canonical_top}' cannot be updated.",
            )
        sdk_top = _sdk_field_name(spec, canonical_top)
        normalized_path = ".".join([sdk_top, *parts[1:]])
        if normalized_path not in normalized:
            normalized.append(normalized_path)

    data_sdk_fields = {_sdk_field_name(spec, item) for item in data}
    mask_top_fields = {item.split(".", 1)[0] for item in normalized}
    if data_sdk_fields != mask_top_fields:
        raise CrudSafetyError(
            "UPDATE_MASK_DATA_MISMATCH",
            "Top-level update_mask fields must match the supplied data fields.",
            {
                "data_fields": sorted(data_sdk_fields),
                "update_mask_fields": sorted(mask_top_fields),
            },
        )
    return normalized


def _default_parent(
    spec: ResourceSpec,
    property_name: str,
    parent: str | None,
    property_num: str,
    config,
) -> str:
    if spec.parent_kind == "property":
        resolved = parent or property_name
        if resolved != property_name:
            raise CrudSafetyError(
                "INVALID_PARENT",
                f"Parent must be '{property_name}' for {spec.name}.",
            )
        return resolved
    if spec.parent_kind == "data_stream":
        if not parent:
            raise CrudSafetyError(
                "PARENT_REQUIRED",
                "A data stream resource name is required as parent.",
            )
        validate_stream_scope(parent, property_num, config)
        return parent
    raise CrudSafetyError(
        "UNSUPPORTED_PARENT_KIND",
        f"Unsupported parent kind '{spec.parent_kind}'.",
    )


def _expected_singleton_name(spec: ResourceSpec, property_name: str) -> str:
    return f"{property_name}/{spec.singleton_suffix}"


def _validate_resource_name(
    spec: ResourceSpec,
    property_name: str,
    property_num: str,
    resource_name: str,
    config,
) -> str:
    if spec.singleton_suffix:
        expected = _expected_singleton_name(spec, property_name)
        if resource_name != expected:
            raise CrudSafetyError(
                "INVALID_RESOURCE_NAME",
                f"Expected singleton resource name '{expected}'.",
            )
        return resource_name

    if spec.parent_kind == "data_stream":
        validate_stream_scope(resource_name, property_num, config)
        marker = f"/{spec.collection_segment}/"
        if marker not in resource_name:
            raise CrudSafetyError(
                "INVALID_RESOURCE_NAME",
                f"Resource name must contain '{marker}'.",
            )
        return resource_name

    expected_prefix = f"{property_name}/{spec.collection_segment}/"
    if not resource_name.startswith(expected_prefix):
        raise CrudSafetyError(
            "INVALID_RESOURCE_NAME",
            f"Resource name must start with '{expected_prefix}'.",
        )
    if "/" in resource_name[len(expected_prefix) :]:
        raise CrudSafetyError(
            "INVALID_RESOURCE_NAME", "Resource name has unexpected segments."
        )
    return resource_name


def _build_message(
    spec: ResourceSpec,
    data: Mapping[str, Any],
    resource_name: str | None = None,
):
    module = _module_for(spec)
    message_class = getattr(module, spec.message_class)
    kwargs = {
        _sdk_field_name(spec, name): value for name, value in data.items()
    }
    if resource_name:
        kwargs["name"] = resource_name
    try:
        return message_class(**kwargs)
    except Exception as exc:
        raise CrudSafetyError(
            "INVALID_RESOURCE_PAYLOAD",
            f"Payload is not valid for {spec.name}: {exc}",
        ) from exc


def _build_request(
    spec: ResourceSpec,
    action: str,
    parent: str | None = None,
    resource_name: str | None = None,
    data: Mapping[str, Any] | None = None,
    update_mask: Sequence[str] | None = None,
):
    module = _module_for(spec)
    request_class = getattr(module, spec.request_classes[action])
    kwargs: Dict[str, Any] = {}
    if action == "create":
        kwargs["parent"] = parent
        kwargs[spec.request_resource_field] = _build_message(spec, data or {})
    elif action == "update":
        kwargs[spec.request_resource_field] = _build_message(
            spec, data or {}, resource_name
        )
        kwargs["update_mask"] = FieldMask(paths=list(update_mask or []))
    elif action == "list":
        kwargs["parent"] = parent
    else:
        kwargs["name"] = resource_name
    try:
        return request_class(**kwargs)
    except Exception as exc:
        raise CrudSafetyError(
            "INVALID_REQUEST_PAYLOAD",
            f"Could not build {action} request for {spec.name}: {exc}",
        ) from exc


def _invoke(spec: ResourceSpec, action: str, request, write: bool = False):
    client = _client_for(spec, write=write)
    method = getattr(client, spec.methods[action])
    return method(request=request)


def _list_sync(spec: ResourceSpec, parent: str) -> List[Dict[str, Any]]:
    request = _build_request(spec, "list", parent=parent)
    pager = _invoke(spec, "list", request, write=False)
    return [proto_to_dict(item) for item in pager]


def _get_sync(spec: ResourceSpec, resource_name: str) -> Dict[str, Any]:
    if "get" in spec.actions:
        request = _build_request(
            spec, "get", resource_name=resource_name
        )
        return proto_to_dict(_invoke(spec, "get", request, write=False))

    if "list" not in spec.actions:
        raise CrudSafetyError(
            "GET_NOT_SUPPORTED",
            f"{spec.name} cannot be read by name through this CRUD layer.",
        )
    marker = f"/{spec.collection_segment}/"
    parent = resource_name.split(marker, 1)[0]
    for item in _list_sync(spec, parent):
        if item.get("name") == resource_name:
            return item
    raise CrudSafetyError(
        "RESOURCE_NOT_FOUND", f"Resource '{resource_name}' was not found."
    )


def _snapshot_sync(
    spec: ResourceSpec,
    action: str,
    parent: str | None,
    resource_name: str | None,
) -> Dict[str, Any]:
    if action == "create":
        if "list" not in spec.actions or not parent:
            return {"kind": "none", "value": None}
        resources = _list_sync(spec, parent)
        resources.sort(key=lambda item: str(item.get("name", "")))
        return {"kind": "collection", "value": resources}
    if not resource_name:
        raise CrudSafetyError(
            "RESOURCE_NAME_REQUIRED", "resource_name is required."
        )
    return {"kind": "resource", "value": _get_sync(spec, resource_name)}


def _normalize_operation_sync(
    property_id: str,
    operation: Mapping[str, Any],
    config,
) -> Dict[str, Any]:
    action = str(operation.get("action", "")).lower()
    resource = str(operation.get("resource", ""))
    spec = get_resource_spec(resource)
    if action not in spec.actions or action not in _MUTATING_ACTIONS:
        raise CrudSafetyError(
            "ACTION_NOT_SUPPORTED",
            f"Action '{action}' is not supported for {resource}.",
            {"supported_actions": list(spec.actions)},
        )
    enforce_action_gates(
        spec.name,
        action,
        spec.api_channel,
        spec.risk_gate,
        config,
    )

    property_name, property_num = _property_parts(property_id)
    validate_property_scope(property_num, operation, config)
    resource_name = operation.get("resource_name")
    requested_parent = operation.get("parent")
    if (
        spec.parent_kind == "data_stream"
        and not requested_parent
        and isinstance(resource_name, str)
    ):
        marker = f"/{spec.collection_segment}/"
        if marker in resource_name:
            requested_parent = resource_name.split(marker, 1)[0]
    parent = _default_parent(
        spec,
        property_name,
        requested_parent,
        property_num,
        config,
    )
    if spec.singleton_suffix and not resource_name:
        resource_name = _expected_singleton_name(spec, property_name)
    if action != "create":
        if not isinstance(resource_name, str) or not resource_name:
            raise CrudSafetyError(
                "RESOURCE_NAME_REQUIRED",
                f"resource_name is required for {action}.",
            )
        resource_name = _validate_resource_name(
            spec,
            property_name,
            property_num,
            resource_name,
            config,
        )

    data = _normalize_data(spec, action, operation.get("data"))
    update_mask: List[str] = []
    if action == "update":
        update_mask = _normalize_update_mask(
            spec, data, operation.get("update_mask")
        )

    _build_request(
        spec,
        action,
        parent=parent,
        resource_name=resource_name,
        data=data,
        update_mask=update_mask,
    )
    snapshot = _snapshot_sync(spec, action, parent, resource_name)
    return {
        "action": action,
        "resource": spec.name,
        "api_channel": spec.api_channel,
        "parent": parent,
        "resource_name": resource_name,
        "data": data,
        "update_mask": update_mask,
        "precondition_hash": snapshot_hash(snapshot),
    }


def _normalize_batch_sync(
    property_id: str,
    operations: Sequence[Mapping[str, Any]],
    config,
) -> List[Dict[str, Any]]:
    return [
        _normalize_operation_sync(property_id, operation, config)
        for operation in operations
    ]


def _operation_scope(operations: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    actions = Counter(str(item["action"]) for item in operations)
    resources = Counter(str(item["resource"]) for item in operations)
    names = sorted(
        str(item["resource_name"])
        for item in operations
        if item.get("resource_name")
    )
    return {
        "actions": dict(actions),
        "resources": dict(resources),
        "requested_resource_names": names,
        "contains_delete": actions.get("delete", 0) > 0,
        "contains_archive": actions.get("archive", 0) > 0,
        "atomic": False,
        "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
    }


def _iso_time(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _validation_response(
    property_num: str,
    normalized: List[Dict[str, Any]],
    config,
) -> Dict[str, Any]:
    signed_payload = {
        "property_id": property_num,
        "operations": normalized,
        "atomic": False,
        "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
    }
    receipt = issue_confirmation(
        signed_payload,
        property_num,
        config.confirmation_ttl_seconds,
    )
    expires_epoch = receipt.pop("confirmation_expires_at_epoch")
    response = {
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
        ),
    )


def _execute_one_sync(operation: Mapping[str, Any]) -> Dict[str, Any]:
    spec = get_resource_spec(str(operation["resource"]))
    action = str(operation["action"])
    request = _build_request(
        spec,
        action,
        parent=operation.get("parent"),
        resource_name=operation.get("resource_name"),
        data=operation.get("data"),
        update_mask=operation.get("update_mask"),
    )
    response = _invoke(spec, action, request, write=True)
    response_dict = None
    if response is not None and hasattr(type(response), "to_dict"):
        response_dict = proto_to_dict(response)

    observed = None
    observed_name = operation.get("resource_name")
    if action == "create" and response_dict:
        observed_name = response_dict.get("name")
    if action in {"create", "update"} and observed_name:
        observed = _get_sync(spec, str(observed_name))
    elif action in {"archive", "delete"} and observed_name:
        try:
            observed = _get_sync(spec, str(observed_name))
        except CrudSafetyError as exc:
            if exc.code == "RESOURCE_NOT_FOUND":
                observed = None
            else:
                raise

    return {
        "action": action,
        "resource": spec.name,
        "resource_name": observed_name,
        "response": response_dict,
        "post_execution_observation": observed,
    }


async def analytics_list_mutable_resources() -> List[Dict[str, Any]]:
    """Lists Admin API resources supported by the protected CRUD layer."""
    return [
        {
            "resource": spec.name,
            "api_channel": spec.api_channel,
            "actions": list(spec.actions),
            "risk_gate": spec.risk_gate,
        }
        for spec in list_resource_specs()
    ]


async def analytics_get_mutation_schema(resource: str) -> Dict[str, Any]:
    """Returns the protected mutation schema for one resource type."""
    return get_resource_spec(resource).schema()


async def analytics_get_resource(
    property_id: int | str,
    resource: str,
    resource_name: str | None = None,
) -> Dict[str, Any]:
    """Reads one registered Admin API resource."""
    spec = get_resource_spec(resource)
    property_name, property_num = _property_parts(property_id)
    config = load_safety_config()
    validate_property_scope(
        property_num, {"resource_name": resource_name}, config
    )
    if spec.singleton_suffix and not resource_name:
        resource_name = _expected_singleton_name(spec, property_name)
    if not resource_name:
        raise CrudSafetyError(
            "RESOURCE_NAME_REQUIRED", "resource_name is required."
        )
    resource_name = _validate_resource_name(
        spec, property_name, property_num, resource_name, config
    )
    return await asyncio.to_thread(_get_sync, spec, resource_name)


async def analytics_list_resources(
    property_id: int | str,
    resource: str,
    parent: str | None = None,
) -> List[Dict[str, Any]]:
    """Lists registered Admin API resources under a property or stream."""
    spec = get_resource_spec(resource)
    if "list" not in spec.actions:
        raise CrudSafetyError(
            "LIST_NOT_SUPPORTED", f"{resource} does not support list."
        )
    property_name, property_num = _property_parts(property_id)
    config = load_safety_config()
    resolved_parent = _default_parent(
        spec, property_name, parent, property_num, config
    )
    validate_property_scope(
        property_num, {"parent": resolved_parent}, config
    )
    return await asyncio.to_thread(_list_sync, spec, resolved_parent)


async def analytics_batch_operations(
    property_id: int | str,
    operations: List[Dict[str, Any]],
    validate_only: bool = True,
    confirmation: str | None = None,
) -> Dict[str, Any]:
    """Validates or executes a protected non-atomic Admin API batch."""
    property_name, property_num = _property_parts(property_id)
    del property_name
    config = load_safety_config()
    materialized = validate_operation_count(operations, config)
    validate_property_scope(property_num, materialized, config)

    normalized = await asyncio.to_thread(
        _normalize_batch_sync,
        property_num,
        materialized,
        config,
    )

    if validate_only:
        return _validation_response(property_num, normalized, config)

    if not confirmation:
        raise CrudSafetyError(
            "CONFIRMATION_REQUIRED",
            "A signed confirmation from a prior validation is required.",
        )
    signed_payload = {
        "property_id": property_num,
        "operations": normalized,
        "atomic": False,
        "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
    }
    confirmation_info = verify_and_register_confirmation(
        confirmation, signed_payload, property_num
    )

    results: List[Dict[str, Any]] = []
    attempted = 0
    for index, operation in enumerate(normalized):
        attempted += 1
        try:
            result = await asyncio.to_thread(_execute_one_sync, operation)
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

    return {
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


async def analytics_create_resource(
    property_id: int | str,
    resource: str,
    data: Dict[str, Any],
    parent: str | None = None,
    validate_only: bool = True,
    confirmation: str | None = None,
) -> Dict[str, Any]:
    """Creates one resource through the protected CRUD engine."""
    operation = {
        "action": "create",
        "resource": resource,
        "parent": parent,
        "data": data,
    }
    return await analytics_batch_operations(
        property_id, [operation], validate_only, confirmation
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
    """Updates one resource through the protected CRUD engine."""
    operation = {
        "action": "update",
        "resource": resource,
        "resource_name": resource_name,
        "data": data,
        "update_mask": update_mask,
    }
    return await analytics_batch_operations(
        property_id, [operation], validate_only, confirmation
    )


async def analytics_archive_resource(
    property_id: int | str,
    resource: str,
    resource_name: str,
    validate_only: bool = True,
    confirmation: str | None = None,
) -> Dict[str, Any]:
    """Archives one resource through the protected CRUD engine."""
    operation = {
        "action": "archive",
        "resource": resource,
        "resource_name": resource_name,
    }
    return await analytics_batch_operations(
        property_id, [operation], validate_only, confirmation
    )


async def analytics_delete_resource(
    property_id: int | str,
    resource: str,
    resource_name: str,
    validate_only: bool = True,
    confirmation: str | None = None,
) -> Dict[str, Any]:
    """Deletes one resource through the protected CRUD engine."""
    operation = {
        "action": "delete",
        "resource": resource,
        "resource_name": resource_name,
    }
    return await analytics_batch_operations(
        property_id, [operation], validate_only, confirmation
    )

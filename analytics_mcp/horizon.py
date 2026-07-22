# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0

"""FastMCP server factory for managed HTTP deployments such as Horizon."""

from __future__ import annotations

import base64
import inspect
import json
import os
from functools import wraps
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.tools import Tool
from mcp.types import ToolAnnotations

from analytics_mcp.tools.admin.crud_hardened import (
    analytics_archive_resource,
    analytics_batch_operations,
    analytics_create_resource,
    analytics_delete_resource,
    analytics_get_mutation_schema,
    analytics_get_resource,
    analytics_list_mutable_resources,
    analytics_list_resources,
    analytics_safety_status,
    analytics_update_resource,
)
from analytics_mcp.tools.admin.crud_safety import CrudSafetyError
from analytics_mcp.tools.admin.info import (
    get_account_summaries,
    get_property_details,
    list_google_ads_links,
    list_property_annotations,
)
from analytics_mcp.tools.reporting.conversions import (
    _run_conversions_report_description,
    run_conversions_report,
)
from analytics_mcp.tools.reporting.core import (
    _run_report_description,
    run_report,
)
from analytics_mcp.tools.reporting.funnel import (
    _run_funnel_report_description,
    run_funnel_report,
)
from analytics_mcp.tools.reporting.metadata import (
    get_custom_dimensions_and_metrics,
)
from analytics_mcp.tools.reporting.realtime import (
    _run_realtime_report_description,
    run_realtime_report,
)

ToolFunction = Callable[..., Awaitable[Any]]

_READ_TOOLS: tuple[tuple[ToolFunction, str | None], ...] = (
    (get_account_summaries, None),
    (list_google_ads_links, None),
    (get_property_details, None),
    (list_property_annotations, None),
    (get_custom_dimensions_and_metrics, None),
    (run_report, _run_report_description()),
    (run_realtime_report, _run_realtime_report_description()),
    (run_funnel_report, _run_funnel_report_description()),
    (run_conversions_report, _run_conversions_report_description()),
    (analytics_safety_status, None),
    (analytics_list_mutable_resources, None),
    (analytics_get_mutation_schema, None),
    (analytics_get_resource, None),
    (analytics_list_resources, None),
)

_MUTATION_TOOLS: tuple[tuple[ToolFunction, str | None], ...] = (
    (analytics_create_resource, None),
    (analytics_update_resource, None),
    (analytics_archive_resource, None),
    (analytics_delete_resource, None),
    (analytics_batch_operations, None),
)


def configure_adc_from_base64() -> Path | None:
    """Materializes optional base64-encoded ADC credentials for Horizon.

    Workload identity or an already configured GOOGLE_APPLICATION_CREDENTIALS
    path remains supported when the base64 environment variable is absent.
    """
    encoded = os.getenv(
        "GOOGLE_APPLICATION_CREDENTIALS_JSON_BASE64", ""
    ).strip()
    if not encoded:
        return None

    try:
        raw = base64.b64decode(encoded, validate=True)
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "GOOGLE_APPLICATION_CREDENTIALS_JSON_BASE64 is not valid base64 JSON."
        ) from exc

    if not isinstance(parsed, dict):
        raise RuntimeError(
            "GOOGLE_APPLICATION_CREDENTIALS_JSON_BASE64 must decode to a JSON object."
        )

    credentials_path = Path(
        os.getenv(
            "GOOGLE_ANALYTICS_ADC_PATH",
            "/tmp/google-analytics-adc.json",
        )
    )
    credentials_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = credentials_path.with_suffix(
        credentials_path.suffix + ".tmp"
    )
    temporary_path.write_bytes(raw)
    temporary_path.chmod(0o600)
    temporary_path.replace(credentials_path)
    credentials_path.chmod(0o600)
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(credentials_path)
    return credentials_path


def _build_auth() -> GoogleProvider | None:
    client_id = os.getenv("GOOGLE_ANALYTICS_MCP_OAUTH_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_ANALYTICS_MCP_OAUTH_CLIENT_SECRET")
    if bool(client_id) != bool(client_secret):
        raise RuntimeError(
            "GOOGLE_ANALYTICS_MCP_OAUTH_CLIENT_ID and "
            "GOOGLE_ANALYTICS_MCP_OAUTH_CLIENT_SECRET must be configured together."
        )
    if not client_id or not client_secret:
        return None

    base_url = os.getenv(
        "GOOGLE_ANALYTICS_MCP_BASE_URL",
        "http://localhost:8080",
    ).rstrip("/")
    return GoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        required_scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
    )


def _with_structured_errors(function: ToolFunction) -> ToolFunction:
    """Preserves the existing JSON error contract under FastMCP."""

    @wraps(function)
    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return await function(*args, **kwargs)
        except CrudSafetyError as exc:
            return {
                "error": {
                    "type": type(exc).__name__,
                    **exc.as_dict(),
                }
            }
        except Exception as exc:  # The low-level server serializes all errors.
            return {
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            }

    wrapped.__signature__ = inspect.signature(function)  # type: ignore[attr-defined]
    return wrapped


def _add_tool(
    server: FastMCP,
    function: ToolFunction,
    *,
    read_only: bool,
    description: str | None,
) -> None:
    wrapped = _with_structured_errors(function)
    if description:
        wrapped.__doc__ = description
    server.add_tool(
        Tool.from_function(
            wrapped,
            annotations=ToolAnnotations(readOnlyHint=read_only),
        )
    )


def create_horizon_server() -> FastMCP:
    """Creates the FastMCP instance consumed by Prefect Horizon."""
    configure_adc_from_base64()
    server = FastMCP(
        "Google Analytics MCP Server",
        auth=_build_auth(),
    )

    for function, description in _READ_TOOLS:
        _add_tool(
            server,
            function,
            read_only=True,
            description=description,
        )
    for function, description in _MUTATION_TOOLS:
        _add_tool(
            server,
            function,
            read_only=False,
            description=description,
        )
    return server

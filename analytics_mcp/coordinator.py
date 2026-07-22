# Copyright 2025 Google LLC All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0

"""Module declaring the singleton MCP server.

The singleton allows other modules to register their tools with the same MCP
server.
"""

import json
import sys

from google.adk.tools.function_tool import FunctionTool
from google.adk.tools.mcp_tool.conversion_utils import adk_to_mcp_tool_type
from mcp import types as mcp_types
from mcp.server.lowlevel import Server

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

run_report_with_description = FunctionTool(run_report)
run_report_with_description.description = _run_report_description()
run_realtime_report_with_description = FunctionTool(run_realtime_report)
run_realtime_report_with_description.description = (
    _run_realtime_report_description()
)
run_funnel_report_with_description = FunctionTool(run_funnel_report)
run_funnel_report_with_description.description = (
    _run_funnel_report_description()
)
run_conversions_report_with_description = FunctionTool(run_conversions_report)
run_conversions_report_with_description.description = (
    _run_conversions_report_description()
)

tools = [
    FunctionTool(get_account_summaries),
    FunctionTool(list_google_ads_links),
    FunctionTool(get_property_details),
    FunctionTool(list_property_annotations),
    FunctionTool(get_custom_dimensions_and_metrics),
    run_report_with_description,
    run_realtime_report_with_description,
    run_funnel_report_with_description,
    run_conversions_report_with_description,
    FunctionTool(analytics_safety_status),
    FunctionTool(analytics_list_mutable_resources),
    FunctionTool(analytics_get_mutation_schema),
    FunctionTool(analytics_get_resource),
    FunctionTool(analytics_list_resources),
    FunctionTool(analytics_create_resource),
    FunctionTool(analytics_update_resource),
    FunctionTool(analytics_archive_resource),
    FunctionTool(analytics_delete_resource),
    FunctionTool(analytics_batch_operations),
]

tool_map = {tool.name: tool for tool in tools}

app = Server(name="Google Analytics MCP Server")

mcp_tools = [adk_to_mcp_tool_type(tool) for tool in tools]


def sanitize_mcp_schema_properties(node: dict) -> None:
    """Ensures additionalProperties is compatible with MCP clients."""
    if not isinstance(node, dict):
        return
    if "additionalProperties" in node:
        value = node["additionalProperties"]
        if not isinstance(value, bool):
            node["additionalProperties"] = True
    for child in node.values():
        if isinstance(child, dict):
            sanitize_mcp_schema_properties(child)
        elif isinstance(child, list):
            for element in child:
                if isinstance(element, dict):
                    sanitize_mcp_schema_properties(element)


for tool in mcp_tools:
    if tool.inputSchema == {}:
        tool.inputSchema = {"type": "object", "properties": {}}
    for prop in tool.inputSchema.get("properties", {}).values():
        if "anyOf" in prop and prop.get("type") == "null":
            del prop["type"]
    sanitize_mcp_schema_properties(tool.inputSchema)
    if tool.name == "run_report":
        tool.inputSchema["required"] = [
            "property_id",
            "date_ranges",
            "dimensions",
            "metrics",
        ]
    elif tool.name == "run_realtime_report":
        tool.inputSchema["required"] = [
            "property_id",
            "dimensions",
            "metrics",
        ]
    elif tool.name == "run_conversions_report":
        tool.inputSchema["required"] = [
            "property_id",
            "date_ranges",
            "dimensions",
            "metrics",
            "conversion_spec",
        ]


@app.list_tools()
async def list_tools() -> list[mcp_types.Tool]:
    return mcp_tools


@app.call_tool()
async def call_mcp_tool(name: str, arguments: dict) -> list[mcp_types.Content]:
    if name in tool_map:
        tool = tool_map[name]
        try:
            response = await tool.run_async(args=arguments, tool_context=None)
            response_text = json.dumps(response, indent=2)
            return [mcp_types.TextContent(type="text", text=response_text)]
        except Exception as exc:
            print(
                f"MCP Server: Error executing ADK tool '{name}': {exc}",
                file=sys.stderr,
            )
            if hasattr(exc, "as_dict"):
                error_payload = exc.as_dict()
                error_payload["type"] = type(exc).__name__
            else:
                error_payload = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            error_text = json.dumps({"error": error_payload})
            return [mcp_types.TextContent(type="text", text=error_text)]

    error_text = json.dumps(
        {"error": f"Tool '{name}' not implemented by this server."}
    )
    return [mcp_types.TextContent(type="text", text=error_text)]

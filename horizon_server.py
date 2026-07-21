"""Prefect Horizon entrypoint for the Google Analytics MCP server."""

from analytics_mcp.horizon import create_horizon_server

mcp = create_horizon_server()

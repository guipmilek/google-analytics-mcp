# Copyright 2026 Google LLC

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastmcp import FastMCP

from analytics_mcp.horizon import (
    configure_deployment_credentials,
    create_horizon_server,
)


class HorizonServerTest(unittest.TestCase):

    def test_configure_deployment_credentials(self):
        credentials = {
            "type": "service_account",
            "project_id": "polisteel-marketing-2026",
        }
        encoded = base64.b64encode(
            json.dumps({"google_credentials": credentials}).encode("utf-8")
        ).decode("ascii")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adc.json"
            environment = {"MCP_CREDENTIALS": encoded}
            with (
                patch.dict(os.environ, environment, clear=True),
                patch("analytics_mcp.horizon._ADC_PATH", path),
            ):
                configured = configure_deployment_credentials()
                self.assertEqual(path, configured)
                self.assertEqual(
                    str(path),
                    os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
                )
                self.assertEqual(credentials, json.loads(path.read_text()))

    def test_invalid_base64_credentials_are_rejected(self):
        with patch.dict(
            os.environ,
            {"MCP_CREDENTIALS": "not base64!"},
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                configure_deployment_credentials()

    def test_legacy_raw_credentials_are_materialized(self):
        credentials = {
            "type": "service_account",
            "project_id": "polisteel-marketing-2026",
        }
        encoded = base64.b64encode(
            json.dumps(credentials).encode("utf-8")
        ).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adc.json"
            with (
                patch.dict(
                    os.environ,
                    {
                        "GOOGLE_APPLICATION_CREDENTIALS_JSON_BASE64": encoded
                    },
                    clear=True,
                ),
                patch("analytics_mcp.horizon._ADC_PATH", path),
            ):
                configured = configure_deployment_credentials()
                self.assertEqual(path, configured)
                self.assertEqual(credentials, json.loads(path.read_text()))

    def test_server_exposes_all_existing_tools(self):
        with patch.dict(os.environ, {}, clear=True):
            server = create_horizon_server()

        self.assertIsInstance(server, FastMCP)
        components = {
            component.name: component
            for key, component in server.local_provider._components.items()
            if key.startswith("tool:")
        }
        self.assertEqual(
            {
                "get_account_summaries",
                "list_google_ads_links",
                "get_property_details",
                "list_property_annotations",
                "get_custom_dimensions_and_metrics",
                "run_report",
                "run_realtime_report",
                "run_funnel_report",
                "run_conversions_report",
                "analytics_crud_status",
                "analytics_list_mutable_resources",
                "analytics_get_mutation_schema",
                "analytics_get_resource",
                "analytics_list_resources",
                "analytics_create_resource",
                "analytics_update_resource",
                "analytics_archive_resource",
                "analytics_delete_resource",
                "analytics_batch_operations",
            },
            set(components),
        )
        self.assertTrue(
            components["analytics_crud_status"].annotations.readOnlyHint
        )
        self.assertTrue(
            components["analytics_delete_resource"].annotations.destructiveHint
        )
        self.assertTrue(
            components["analytics_delete_resource"].annotations.idempotentHint
        )
        self.assertTrue(
            components["analytics_delete_resource"].annotations.openWorldHint
        )

    def test_partial_oauth_configuration_is_rejected(self):
        with patch.dict(
            os.environ,
            {"GOOGLE_ANALYTICS_MCP_OAUTH_CLIENT_ID": "client-id"},
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                create_horizon_server()


if __name__ == "__main__":
    unittest.main()

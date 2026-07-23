# Copyright 2026 Google LLC

import asyncio
import json
import os
import unittest
from unittest.mock import patch

from analytics_mcp.tools.admin import crud_safety


class CrudSafetyTest(unittest.TestCase):

    def _environment(self):
        return {
            "MCP_CONFIG": json.dumps(
                {
                    "accounts": ["401804063"],
                    "properties": ["546475155"],
                    "data_streams": ["15297504355"],
                    "ads_customers": ["8448275903"],
                }
            )
        }

    def test_operation_hash_is_stable_and_128_bit(self):
        first = crud_safety.operation_hash({"b": 2, "a": 1})
        second = crud_safety.operation_hash({"a": 1, "b": 2})
        self.assertEqual(first, second)
        self.assertEqual(32, len(first))

    def test_legacy_gate_environment_is_ignored(self):
        environment = {
            **self._environment(),
            "GOOGLE_ANALYTICS_ADMIN_MUTATIONS_ENABLED": "false",
            "GOOGLE_ANALYTICS_ALLOW_DELETE": "false",
            "GOOGLE_ANALYTICS_CONFIRMATION_SECRET": "unused",
        }
        with patch.dict(os.environ, environment, clear=True):
            crud_safety.load_safety_config()
            status = asyncio.run(crud_safety.analytics_crud_status())
        self.assertEqual("direct-crud-v1", status["contract_version"])
        self.assertEqual("DIRECT", status["write_mode"])
        self.assertFalse(status["approval_workflow"])
        self.assertNotIn("gates", status)
        self.assertNotIn("confirmation_secret_configured", status)

    def test_property_allowlist_rejects_cross_property_reference(self):
        with patch.dict(os.environ, self._environment(), clear=True):
            config = crud_safety.load_safety_config()
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.validate_property_scope(
                    "546475155",
                    {"name": "properties/999/customDimensions/1"},
                    config,
                )
            self.assertEqual("CROSS_PROPERTY_REFERENCE", context.exception.code)

    def test_data_stream_allowlist(self):
        with patch.dict(os.environ, self._environment(), clear=True):
            config = crud_safety.load_safety_config()
            crud_safety.validate_stream_scope(
                "properties/546475155/dataStreams/15297504355",
                "546475155",
                config,
            )
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.validate_stream_scope(
                    "properties/546475155/dataStreams/1",
                    "546475155",
                    config,
                )
            self.assertEqual("DATA_STREAM_NOT_ALLOWED", context.exception.code)

    def test_empty_allowlists_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            config = crud_safety.load_safety_config()
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.validate_property_scope("546475155", {}, config)
        self.assertEqual("PROPERTY_ALLOWLIST_EMPTY", context.exception.code)


if __name__ == "__main__":
    unittest.main()

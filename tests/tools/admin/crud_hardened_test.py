# Copyright 2026 Google LLC

import asyncio
import inspect
import json
import os
import unittest
from unittest.mock import AsyncMock, patch

from google.analytics import admin_v1beta
from google.api_core import exceptions as google_exceptions

from analytics_mcp.tools.admin import crud_hardened
from analytics_mcp.tools.admin.crud_safety import CrudSafetyError


class CrudHardenedTest(unittest.TestCase):

    def _environment(self):
        return {
            "MCP_CONFIG": json.dumps(
                {
                    "accounts": ["401804063"],
                    "properties": ["546475155"],
                    "data_streams": ["15297504355"],
                }
            )
        }

    def test_data_stream_mutation_honors_stream_allowlist(self):
        operations = [
            {
                "action": "update",
                "resource": "DataStream",
                "resource_name": (
                    "properties/546475155/dataStreams/15297504355"
                ),
            }
        ]
        with patch.dict(os.environ, self._environment(), clear=True):
            crud_hardened._validate_data_stream_mutation_scope(
                "546475155", operations
            )
            operations[0][
                "resource_name"
            ] = "properties/546475155/dataStreams/1"
            with self.assertRaises(CrudSafetyError) as context:
                crud_hardened._validate_data_stream_mutation_scope(
                    "546475155", operations
                )
            self.assertEqual("DATA_STREAM_NOT_ALLOWED", context.exception.code)

    @patch.object(crud_hardened._crud, "_build_request", return_value=object())
    @patch.object(
        crud_hardened._crud,
        "_get_sync",
        side_effect=RuntimeError("read failed"),
    )
    @patch.object(crud_hardened._crud, "_invoke")
    def test_post_read_failure_does_not_reclassify_dispatch(
        self, invoke, unused_get, unused_build
    ):
        invoke.return_value = admin_v1beta.CustomDimension(
            name="properties/546475155/customDimensions/1"
        )
        result = crud_hardened._safe_execute_one_sync(
            {
                "action": "update",
                "resource": "CustomDimension",
                "resource_name": "properties/546475155/customDimensions/1",
                "data": {"display_name": "Lead"},
                "update_mask": ["display_name"],
            }
        )
        self.assertEqual("FAILED", result["post_execution_verification_status"])
        self.assertEqual(
            "read failed",
            result["post_execution_verification_error"]["message"],
        )

    @patch.object(crud_hardened._crud, "_build_request", return_value=object())
    @patch.object(
        crud_hardened._crud,
        "_get_sync",
        side_effect=google_exceptions.NotFound("gone"),
    )
    @patch.object(crud_hardened._crud, "_invoke", return_value=None)
    def test_not_found_verifies_delete(
        self, unused_invoke, unused_get, unused_build
    ):
        result = crud_hardened._safe_execute_one_sync(
            {
                "action": "delete",
                "resource": "KeyEvent",
                "resource_name": "properties/546475155/keyEvents/1",
                "data": {},
                "update_mask": [],
            }
        )
        self.assertEqual(
            "VERIFIED", result["post_execution_verification_status"]
        )

    def test_verification_warning_summary(self):
        result = {
            "mode": "EXECUTE",
            "execution_status": "SUCCEEDED",
            "results": [{"post_execution_verification_status": "FAILED"}],
        }
        summarized = crud_hardened._add_verification_summary(result)
        self.assertEqual(
            "SUCCEEDED_WITH_VERIFICATION_WARNINGS",
            summarized["execution_status"],
        )
        self.assertFalse(
            summarized["verification"]["all_requested_resources_verified"]
        )

    def test_public_writes_have_direct_dry_run_contract(self):
        for function in (
            crud_hardened.analytics_create_resource,
            crud_hardened.analytics_update_resource,
            crud_hardened.analytics_archive_resource,
            crud_hardened.analytics_delete_resource,
            crud_hardened.analytics_batch_operations,
        ):
            parameters = inspect.signature(function).parameters
            self.assertIn("dry_run", parameters)
            self.assertNotIn("validate_only", parameters)
            self.assertNotIn("confirmation", parameters)

    def test_dry_run_performs_no_mutation(self):
        normalized = [
            {
                "action": "delete",
                "resource": "KeyEvent",
                "resource_name": "properties/546475155/keyEvents/1",
                "no_op_reason": None,
                "precondition_hash": "a" * 64,
            }
        ]
        with (
            patch.dict(os.environ, self._environment(), clear=True),
            patch.object(
                crud_hardened,
                "_account_context_sync",
                return_value={
                    "account_id": "401804063",
                    "property_parent": "accounts/401804063",
                    "property_parent_precondition_hash": "b" * 64,
                },
            ),
            patch.object(
                crud_hardened._crud,
                "_normalize_batch_sync",
                return_value=normalized,
            ),
            patch.object(
                crud_hardened,
                "_validate_google_ads_link_operations_sync",
                return_value=normalized,
            ),
            patch.object(
                crud_hardened,
                "_safe_execute_one_sync",
            ) as execute,
        ):
            result = asyncio.run(
                crud_hardened.analytics_batch_operations(
                    "546475155",
                    [
                        {
                            "action": "delete",
                            "resource": "KeyEvent",
                            "resource_name": (
                                "properties/546475155/keyEvents/1"
                            ),
                        }
                    ],
                    dry_run=True,
                )
            )
        self.assertEqual("NOT_EXECUTED", result["execution_status"])
        self.assertFalse(result["verification"]["admin_api_mutation_sent"])
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()

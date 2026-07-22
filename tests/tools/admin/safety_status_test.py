# Copyright 2026 Google LLC

import asyncio
import json
import os
import unittest
from unittest.mock import patch

from analytics_mcp.tools.admin import crud_hardened, crud_safety
from analytics_mcp.tools.admin.crud_registry import get_resource_spec


class AnalyticsSafetyStatusTest(unittest.TestCase):

    def setUp(self):
        crud_safety._USED_CONFIRMATIONS.clear()

    def _enabled_environment(self):
        return {
            "GOOGLE_ANALYTICS_ADMIN_MUTATIONS_ENABLED": "true",
            "GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS": "401804063",
            "GOOGLE_ANALYTICS_ALLOWED_PROPERTY_IDS": "546475155",
            "GOOGLE_ANALYTICS_ALLOWED_DATA_STREAM_IDS": "15297504355",
            "GOOGLE_ANALYTICS_ALLOWED_GOOGLE_ADS_CUSTOMER_IDS": "8448275903",
            "GOOGLE_ANALYTICS_MAX_OPERATIONS_PER_REQUEST": "10",
            "GOOGLE_ANALYTICS_CONFIRMATION_TTL_SECONDS": "900",
            "GOOGLE_ANALYTICS_CONFIRMATION_SECRET": "x" * 48,
            "GOOGLE_ANALYTICS_ALLOW_CREATE": "true",
            "GOOGLE_ANALYTICS_ALLOW_UPDATE": "true",
            "GOOGLE_ANALYTICS_ALLOW_DELETE": "true",
            "GOOGLE_ANALYTICS_ALLOW_ARCHIVE": "true",
            "GOOGLE_ANALYTICS_ALLOW_PROPERTY_UPDATE": "true",
            "GOOGLE_ANALYTICS_ALLOW_DATA_STREAM_CHANGES": "true",
            "GOOGLE_ANALYTICS_ALLOW_KEY_EVENT_CHANGES": "true",
            "GOOGLE_ANALYTICS_ALLOW_CUSTOM_DIMENSION_CHANGES": "true",
            "GOOGLE_ANALYTICS_ALLOW_CUSTOM_METRIC_CHANGES": "true",
            "GOOGLE_ANALYTICS_ALLOW_RETENTION_CHANGES": "true",
            "GOOGLE_ANALYTICS_ALLOW_ATTRIBUTION_CHANGES": "true",
            "GOOGLE_ANALYTICS_ALLOW_LINK_CHANGES": "true",
            "GOOGLE_ANALYTICS_ALLOW_MEASUREMENT_PROTOCOL_SECRET_CHANGES": (
                "true"
            ),
            "GOOGLE_ANALYTICS_ALLOW_ALPHA_RESOURCES": "true",
        }

    def test_status_defaults_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            result = asyncio.run(crud_safety.analytics_safety_status())

        self.assertFalse(result["mutations_enabled"])
        self.assertTrue(all(not value for value in result["gates"].values()))
        self.assertEqual([], result["allowlists"]["account_ids"])
        self.assertEqual([], result["allowlists"]["property_ids"])
        self.assertEqual([], result["allowlists"]["data_stream_ids"])
        self.assertEqual([], result["allowlists"]["google_ads_customer_ids"])
        self.assertFalse(result["confirmation_secret_configured"])

    def test_status_reports_enabled_configuration_without_secret(self):
        environment = self._enabled_environment()
        environment["GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS"] = "401804063,100"
        with patch.dict(os.environ, environment, clear=True):
            result = asyncio.run(crud_safety.analytics_safety_status())

        self.assertTrue(result["mutations_enabled"])
        self.assertTrue(all(result["gates"].values()))
        self.assertEqual(
            ["100", "401804063"],
            result["allowlists"]["account_ids"],
        )
        self.assertTrue(result["confirmation_secret_configured"])
        serialized = json.dumps(result)
        self.assertNotIn("x" * 48, serialized)
        self.assertEqual("CONNECTOR_PREFLIGHT", result["validation_kind"])
        self.assertEqual(
            "BEST_EFFORT_PROCESS_LOCAL", result["replay_protection"]
        )
        self.assertFalse(result["globally_single_use"])
        self.assertFalse(result["atomic"])

    def test_create_and_update_are_independently_gated(self):
        environment = self._enabled_environment()
        environment["GOOGLE_ANALYTICS_ALLOW_CREATE"] = "false"
        with patch.dict(os.environ, environment, clear=True):
            config = crud_safety.load_safety_config()
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.enforce_action_gates(
                    "CustomDimension",
                    "create",
                    "beta",
                    "custom_dimension",
                    config,
                )
            self.assertEqual("CREATE_DISABLED", context.exception.code)

        environment = self._enabled_environment()
        environment["GOOGLE_ANALYTICS_ALLOW_UPDATE"] = "false"
        with patch.dict(os.environ, environment, clear=True):
            config = crud_safety.load_safety_config()
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.enforce_action_gates(
                    "DataRetentionSettings",
                    "update",
                    "beta",
                    "retention",
                    config,
                )
            self.assertEqual("UPDATE_DISABLED", context.exception.code)

    def test_custom_resources_have_dedicated_gates(self):
        self.assertEqual(
            "custom_dimension",
            get_resource_spec("CustomDimension").risk_gate,
        )
        self.assertEqual(
            "custom_metric",
            get_resource_spec("CustomMetric").risk_gate,
        )

        environment = self._enabled_environment()
        environment["GOOGLE_ANALYTICS_ALLOW_CUSTOM_DIMENSION_CHANGES"] = "false"
        with patch.dict(os.environ, environment, clear=True):
            config = crud_safety.load_safety_config()
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.enforce_action_gates(
                    "CustomDimension",
                    "create",
                    "beta",
                    "custom_dimension",
                    config,
                )
            self.assertEqual("RESOURCE_GATE_DISABLED", context.exception.code)

    def test_account_allowlist(self):
        environment = self._enabled_environment()
        environment["GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS"] = ""
        with patch.dict(os.environ, environment, clear=True):
            config = crud_safety.load_safety_config()
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.validate_account_scope("401804063", config)
            self.assertEqual("ACCOUNT_ALLOWLIST_EMPTY", context.exception.code)

        environment = self._enabled_environment()
        with patch.dict(os.environ, environment, clear=True):
            config = crud_safety.load_safety_config()
            crud_safety.validate_account_scope("401804063", config)
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.validate_account_scope("999", config)
            self.assertEqual("ACCOUNT_NOT_ALLOWED", context.exception.code)

    def test_google_ads_customer_allowlist(self):
        with patch.dict(os.environ, self._enabled_environment(), clear=True):
            config = crud_safety.load_safety_config()
            crud_safety.validate_google_ads_customer_scope("8448275903", config)
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.validate_google_ads_customer_scope(
                    "7100427642", config
                )
            self.assertEqual(
                "GOOGLE_ADS_CUSTOMER_NOT_ALLOWED", context.exception.code
            )

    @patch.object(
        crud_hardened._crud,
        "_get_sync",
        return_value={
            "name": "properties/546475155/googleAdsLinks/1",
            "customer_id": "8448275903",
        },
    )
    def test_google_ads_delete_reads_customer_before_confirmation(
        self, get_sync
    ):
        operation = {
            "action": "delete",
            "resource": "GoogleAdsLink",
            "resource_name": "properties/546475155/googleAdsLinks/1",
            "data": {},
            "update_mask": [],
        }
        with patch.dict(os.environ, self._enabled_environment(), clear=True):
            config = crud_safety.load_safety_config()
            normalized = (
                crud_hardened._validate_google_ads_link_operations_sync(
                    [operation], config
                )
            )
        get_sync.assert_called_once()
        self.assertEqual("8448275903", normalized[0]["google_ads_customer_id"])

    def test_confirmation_is_bound_to_property_parent_context(self):
        first_payload = {
            "property_id": "546475155",
            "account_id": "401804063",
            "property_parent_precondition_hash": "a" * 64,
            "operations": [],
        }
        second_payload = {
            **first_payload,
            "account_id": "999",
            "property_parent_precondition_hash": "b" * 64,
        }
        with patch.dict(os.environ, self._enabled_environment(), clear=True):
            confirmation = crud_safety.issue_confirmation(
                first_payload, "546475155", 900
            )["required_confirmation"]
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.verify_and_register_confirmation(
                    confirmation, second_payload, "546475155"
                )
            self.assertEqual(
                "PROPERTY_PARENT_ACCOUNT_CHANGED", context.exception.code
            )


if __name__ == "__main__":
    unittest.main()

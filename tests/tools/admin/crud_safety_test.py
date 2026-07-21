# Copyright 2026 Google LLC

import os
import unittest
from unittest.mock import patch

from analytics_mcp.tools.admin import crud_safety


class CrudSafetyTest(unittest.TestCase):

    def setUp(self):
        crud_safety._USED_CONFIRMATIONS.clear()

    def _environment(self):
        return {
            "GOOGLE_ANALYTICS_ADMIN_MUTATIONS_ENABLED": "true",
            "GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS": "401804063",
            "GOOGLE_ANALYTICS_ALLOWED_PROPERTY_IDS": "546475155",
            "GOOGLE_ANALYTICS_ALLOWED_DATA_STREAM_IDS": "15297504355",
            "GOOGLE_ANALYTICS_CONFIRMATION_SECRET": "x" * 48,
        }

    def test_operation_hash_is_stable_and_128_bit(self):
        first = crud_safety.operation_hash({"b": 2, "a": 1})
        second = crud_safety.operation_hash({"a": 1, "b": 2})
        self.assertEqual(first, second)
        self.assertEqual(32, len(first))

    def test_confirmation_verifies_and_blocks_local_replay(self):
        payload = {
            "property_id": "546475155",
            "operations": [{"action": "update"}],
        }
        with patch.dict(os.environ, self._environment(), clear=True):
            issued = crud_safety.issue_confirmation(payload, "546475155", 900)
            confirmation = issued["required_confirmation"]
            verified = crud_safety.verify_and_register_confirmation(
                confirmation, payload, "546475155"
            )
            self.assertTrue(verified["confirmation_verified"])
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.verify_and_register_confirmation(
                    confirmation, payload, "546475155"
                )
            self.assertEqual("CONFIRMATION_REPLAYED", context.exception.code)

    def test_confirmation_is_bound_to_property_and_payload(self):
        payload = {"property_id": "546475155", "operations": []}
        with patch.dict(os.environ, self._environment(), clear=True):
            confirmation = crud_safety.issue_confirmation(
                payload, "546475155", 900
            )["required_confirmation"]
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.verify_and_register_confirmation(
                    confirmation,
                    {"property_id": "546475155", "operations": [1]},
                    "546475155",
                )
            self.assertEqual("CONFIRMATION_MISMATCH", context.exception.code)

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

    def test_delete_is_independently_gated(self):
        with patch.dict(os.environ, self._environment(), clear=True):
            config = crud_safety.load_safety_config()
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.enforce_action_gates(
                    "KeyEvent", "delete", "beta", "key_event", config
                )
            self.assertEqual("DELETE_DISABLED", context.exception.code)


if __name__ == "__main__":
    unittest.main()

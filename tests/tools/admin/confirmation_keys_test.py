# Copyright 2026 Google LLC

import asyncio
import json
import os
import unittest
from unittest.mock import patch

from analytics_mcp.tools.admin import confirmation_keys, crud_safety


class ConfirmationKeysTest(unittest.TestCase):

    def setUp(self):
        crud_safety._USED_CONFIRMATIONS.clear()

    def _environment(self, secret: str = "x" * 48):
        return {
            "GOOGLE_ANALYTICS_CONFIRMATION_SECRET": secret,
            "GOOGLE_ANALYTICS_CONFIRMATION_TTL_SECONDS": "900",
        }

    def _payload(self):
        return {
            "property_id": "546475155",
            "account_id": "401804063",
            "property_parent_precondition_hash": "a" * 64,
            "operations": [],
            "atomic": False,
            "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR",
        }

    def test_package_initialization_installs_hardened_helpers(self):
        self.assertIs(
            crud_safety.issue_confirmation, confirmation_keys.issue_confirmation
        )
        self.assertIs(
            crud_safety.verify_and_register_confirmation,
            confirmation_keys.verify_and_register_confirmation,
        )

    def test_receipt_declares_key_and_instance_without_asserting_cross_instance(
        self,
    ):
        with patch.dict(os.environ, self._environment(), clear=True):
            receipt = crud_safety.issue_confirmation(
                self._payload(), "546475155", 900
            )

        self.assertEqual(2, receipt["confirmation_token_version"])
        self.assertEqual(16, len(receipt["confirmation_key_id"]))
        self.assertEqual(
            receipt["confirmation_key_id"],
            receipt["validation_receipt"]["confirmation_key_id"],
        )
        self.assertIsNone(receipt["validation_receipt"]["cross_instance_valid"])
        self.assertEqual(
            "MATCHING_CONFIRMATION_KEY_ID",
            receipt["validation_receipt"]["cross_instance_requirement"],
        )

    def test_same_key_round_trip_remains_valid(self):
        with patch.dict(os.environ, self._environment(), clear=True):
            confirmation = crud_safety.issue_confirmation(
                self._payload(), "546475155", 900
            )["required_confirmation"]
            verified = crud_safety.verify_and_register_confirmation(
                confirmation, self._payload(), "546475155"
            )

        self.assertTrue(verified["confirmation_verified"])
        self.assertEqual("current", verified["confirmation_key_source"])
        self.assertEqual(2, verified["confirmation_token_version"])

    def test_changed_key_returns_specific_mismatch(self):
        old_secret = "old-confirmation-secret-" + "a" * 32
        new_secret = "new-confirmation-secret-" + "b" * 32
        with patch.dict(os.environ, self._environment(old_secret), clear=True):
            confirmation = crud_safety.issue_confirmation(
                self._payload(), "546475155", 900
            )["required_confirmation"]

        with patch.dict(os.environ, self._environment(new_secret), clear=True):
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.verify_and_register_confirmation(
                    confirmation, self._payload(), "546475155"
                )

        self.assertEqual("CONFIRMATION_KEY_MISMATCH", context.exception.code)
        self.assertIn("observed_confirmation_key_id", context.exception.details)
        self.assertIn("current_confirmation_key_id", context.exception.details)

    def test_previous_key_supports_controlled_rotation(self):
        old_secret = "old-confirmation-secret-" + "a" * 32
        new_secret = "new-confirmation-secret-" + "b" * 32
        with patch.dict(os.environ, self._environment(old_secret), clear=True):
            confirmation = crud_safety.issue_confirmation(
                self._payload(), "546475155", 900
            )["required_confirmation"]

        rotated = self._environment(new_secret)
        rotated["GOOGLE_ANALYTICS_CONFIRMATION_PREVIOUS_SECRET"] = old_secret
        with patch.dict(os.environ, rotated, clear=True):
            verified = crud_safety.verify_and_register_confirmation(
                confirmation, self._payload(), "546475155"
            )

        self.assertTrue(verified["confirmation_verified"])
        self.assertEqual("previous", verified["confirmation_key_source"])

    def test_corrupted_signature_remains_invalid_confirmation(self):
        with patch.dict(os.environ, self._environment(), clear=True):
            confirmation = crud_safety.issue_confirmation(
                self._payload(), "546475155", 900
            )["required_confirmation"]
            prefix, signature = confirmation.rsplit(".", 1)
            replacement = "A" if signature[-1] != "A" else "B"
            corrupted = prefix + "." + signature[:-1] + replacement
            with self.assertRaises(crud_safety.CrudSafetyError) as context:
                crud_safety.verify_and_register_confirmation(
                    corrupted, self._payload(), "546475155"
                )

        self.assertEqual("INVALID_CONFIRMATION", context.exception.code)

    def test_diagnostics_round_trip_is_local_and_does_not_register_replay(self):
        with patch.dict(os.environ, self._environment(), clear=True):
            result = asyncio.run(
                confirmation_keys.analytics_confirmation_diagnostics()
            )

        self.assertTrue(result["self_test"]["issued"])
        self.assertTrue(result["self_test"]["verified"])
        self.assertFalse(result["self_test"]["replay_registered"])
        self.assertEqual({}, crud_safety._USED_CONFIRMATIONS)
        serialized = json.dumps(result)
        self.assertNotIn("x" * 48, serialized)
        self.assertNotIn("required_confirmation", serialized)

    def test_status_exposes_only_non_secret_diagnostics(self):
        environment = self._environment()
        environment["GOOGLE_ANALYTICS_CONFIRMATION_PREVIOUS_SECRET"] = "short"
        with patch.dict(os.environ, environment, clear=True):
            result = asyncio.run(crud_safety.analytics_safety_status())

        self.assertEqual(16, len(result["confirmation_key_id"]))
        self.assertEqual(16, len(result["process_instance_id"]))
        self.assertTrue(result["previous_confirmation_secret_configured"])
        self.assertFalse(result["previous_confirmation_secret_valid"])
        self.assertIsNone(result["previous_confirmation_key_id"])
        self.assertIsNone(result["cross_instance_valid"])
        self.assertEqual(
            "MATCHING_CONFIRMATION_KEY_ID",
            result["cross_instance_requirement"],
        )


if __name__ == "__main__":
    unittest.main()

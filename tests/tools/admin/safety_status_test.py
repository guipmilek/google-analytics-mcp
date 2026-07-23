# Copyright 2026 Google LLC

import os
import unittest
from unittest.mock import patch

from analytics_mcp.tools.admin import crud_hardened, crud_safety


class AnalyticsScopeTest(unittest.TestCase):

    def _environment(self):
        return {
            "GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS": "401804063",
            "GOOGLE_ANALYTICS_ALLOWED_PROPERTY_IDS": "546475155",
            "GOOGLE_ANALYTICS_ALLOWED_DATA_STREAM_IDS": "15297504355",
            "GOOGLE_ANALYTICS_ALLOWED_GOOGLE_ADS_CUSTOMER_IDS": "8448275903",
        }

    def test_account_and_ads_customer_allowlists(self):
        with patch.dict(os.environ, self._environment(), clear=True):
            config = crud_safety.load_safety_config()
            crud_safety.validate_account_scope("401804063", config)
            crud_safety.validate_google_ads_customer_scope("8448275903", config)
            with self.assertRaises(crud_safety.CrudSafetyError) as account:
                crud_safety.validate_account_scope("999", config)
            with self.assertRaises(crud_safety.CrudSafetyError) as customer:
                crud_safety.validate_google_ads_customer_scope("1", config)
        self.assertEqual("ACCOUNT_NOT_ALLOWED", account.exception.code)
        self.assertEqual(
            "GOOGLE_ADS_CUSTOMER_NOT_ALLOWED", customer.exception.code
        )

    @patch.object(
        crud_hardened._crud,
        "_get_sync",
        return_value={
            "name": "properties/546475155/googleAdsLinks/1",
            "customer_id": "8448275903",
        },
    )
    def test_google_ads_delete_reads_customer_scope(self, get_sync):
        operation = {
            "action": "delete",
            "resource": "GoogleAdsLink",
            "resource_name": "properties/546475155/googleAdsLinks/1",
        }
        with patch.dict(os.environ, self._environment(), clear=True):
            normalized = (
                crud_hardened._validate_google_ads_link_operations_sync(
                    [operation], crud_safety.load_safety_config()
                )
            )
        get_sync.assert_called_once()
        self.assertEqual("8448275903", normalized[0]["google_ads_customer_id"])

    def test_absent_google_ads_link_is_idempotent_without_customer_read(self):
        operation = {
            "action": "delete",
            "resource": "GoogleAdsLink",
            "resource_name": "properties/546475155/googleAdsLinks/1",
            "no_op_reason": "ALREADY_ABSENT",
        }
        with patch.dict(os.environ, self._environment(), clear=True):
            normalized = (
                crud_hardened._validate_google_ads_link_operations_sync(
                    [operation], crud_safety.load_safety_config()
                )
            )
        self.assertEqual("ALREADY_ABSENT", normalized[0]["no_op_reason"])


if __name__ == "__main__":
    unittest.main()

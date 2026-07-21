# Copyright 2026 Google LLC

import unittest

from google.analytics import admin_v1alpha, admin_v1beta

from analytics_mcp.tools.admin.crud_registry import list_resource_specs


class CrudSdkContractTest(unittest.TestCase):

    def test_registry_matches_installed_sdk(self):
        for spec in list_resource_specs():
            module = (
                admin_v1alpha
                if spec.api_channel == "alpha"
                else admin_v1beta
            )
            message_class = getattr(module, spec.message_class)
            client_class = module.AnalyticsAdminServiceClient

            for action in spec.actions:
                self.assertTrue(
                    hasattr(module, spec.request_classes[action]),
                    f"Missing {spec.request_classes[action]}",
                )
                self.assertTrue(
                    hasattr(client_class, spec.methods[action]),
                    f"Missing client method {spec.methods[action]}",
                )

            sdk_fields = set(message_class.meta.fields)
            for field in spec.fields:
                sdk_name = spec.aliases.get(field.name, field.name)
                self.assertIn(
                    sdk_name,
                    sdk_fields,
                    f"Missing field {spec.name}.{sdk_name}",
                )

    def test_request_resource_fields_exist(self):
        for spec in list_resource_specs():
            module = (
                admin_v1alpha
                if spec.api_channel == "alpha"
                else admin_v1beta
            )
            for action in ("create", "update"):
                if action not in spec.actions:
                    continue
                request_class = getattr(module, spec.request_classes[action])
                self.assertIn(
                    spec.request_resource_field,
                    request_class.meta.fields,
                )


if __name__ == "__main__":
    unittest.main()

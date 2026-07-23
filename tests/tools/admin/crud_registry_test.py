# Copyright 2026 Google LLC

import unittest

from analytics_mcp.tools.admin.crud_registry import (
    get_resource_spec,
    list_resource_specs,
)


class CrudRegistryTest(unittest.TestCase):

    def test_expected_resources_are_registered(self):
        names = [item.name for item in list_resource_specs()]
        self.assertEqual(
            [
                "CustomDimension",
                "CustomMetric",
                "KeyEvent",
                "DataStream",
                "MeasurementProtocolSecret",
                "GoogleAdsLink",
                "DataRetentionSettings",
                "AttributionSettings",
            ],
            names,
        )

    def test_schema_exposes_validation_limitations(self):
        schema = get_resource_spec("CustomDimension").schema()
        self.assertIn("dry_run", schema["validation_note"])
        self.assertIn("connector validation", schema["validation_note"])
        self.assertIn("non-atomic", schema["execution_note"])

    def test_data_stream_accepts_type_alias(self):
        spec = get_resource_spec("DataStream")
        self.assertEqual("type_", spec.aliases["type"])

    def test_unknown_resource_is_rejected(self):
        with self.assertRaises(ValueError):
            get_resource_spec("Unknown")


if __name__ == "__main__":
    unittest.main()

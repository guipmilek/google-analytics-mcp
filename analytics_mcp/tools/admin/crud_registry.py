# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0

"""Registry for protected Google Analytics Admin API CRUD resources."""

from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, Mapping, Tuple


@dataclass(frozen=True)
class FieldSpec:
    """Describes a field accepted by the protected CRUD layer."""

    name: str
    field_type: str
    required_on_create: bool = False
    writable_on_create: bool = True
    writable_on_update: bool = True
    immutable: bool = False
    output_only: bool = False
    enum_values: Tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True)
class ResourceSpec:
    """Maps a generic CRUD resource to Admin API client methods."""

    name: str
    api_channel: str
    message_class: str
    parent_kind: str
    collection_segment: str
    actions: Tuple[str, ...]
    methods: Mapping[str, str]
    request_classes: Mapping[str, str]
    request_resource_field: str
    fields: Tuple[FieldSpec, ...]
    risk_gate: str | None = None
    singleton_suffix: str | None = None
    aliases: Mapping[str, str] = field(default_factory=dict)

    def schema(self) -> Dict[str, object]:
        """Returns a JSON-serializable schema for MCP callers."""
        return {
            "resource": self.name,
            "api_channel": self.api_channel,
            "message_class": self.message_class,
            "parent_kind": self.parent_kind,
            "actions": list(self.actions),
            "risk_gate": self.risk_gate,
            "aliases": dict(self.aliases),
            "fields": [asdict(item) for item in self.fields],
            "validation_note": (
                "VALIDATE_ONLY is a connector preflight. The Analytics Admin "
                "API does not provide a generic validate_only mutation mode."
            ),
            "execution_note": (
                "Batch execution is sequential and non-atomic. It stops after "
                "the first failed or unknown operation."
            ),
        }

    @property
    def field_map(self) -> Dict[str, FieldSpec]:
        """Returns fields indexed by their canonical user-facing name."""
        return {item.name: item for item in self.fields}


_RESOURCE_SPECS: Tuple[ResourceSpec, ...] = (
    ResourceSpec(
        name="CustomDimension",
        api_channel="beta",
        message_class="CustomDimension",
        parent_kind="property",
        collection_segment="customDimensions",
        actions=("create", "get", "list", "update", "archive"),
        methods={
            "create": "create_custom_dimension",
            "get": "get_custom_dimension",
            "list": "list_custom_dimensions",
            "update": "update_custom_dimension",
            "archive": "archive_custom_dimension",
        },
        request_classes={
            "create": "CreateCustomDimensionRequest",
            "get": "GetCustomDimensionRequest",
            "list": "ListCustomDimensionsRequest",
            "update": "UpdateCustomDimensionRequest",
            "archive": "ArchiveCustomDimensionRequest",
        },
        request_resource_field="custom_dimension",
        risk_gate=None,
        fields=(
            FieldSpec(
                "name",
                "string",
                writable_on_create=False,
                writable_on_update=False,
                output_only=True,
            ),
            FieldSpec(
                "parameter_name",
                "string",
                required_on_create=True,
                writable_on_update=False,
                immutable=True,
            ),
            FieldSpec("display_name", "string", required_on_create=True),
            FieldSpec("description", "string"),
            FieldSpec(
                "scope",
                "enum",
                required_on_create=True,
                writable_on_update=False,
                immutable=True,
                enum_values=("EVENT", "USER", "ITEM"),
            ),
            FieldSpec("disallow_ads_personalization", "bool"),
        ),
    ),
    ResourceSpec(
        name="CustomMetric",
        api_channel="beta",
        message_class="CustomMetric",
        parent_kind="property",
        collection_segment="customMetrics",
        actions=("create", "get", "list", "update", "archive"),
        methods={
            "create": "create_custom_metric",
            "get": "get_custom_metric",
            "list": "list_custom_metrics",
            "update": "update_custom_metric",
            "archive": "archive_custom_metric",
        },
        request_classes={
            "create": "CreateCustomMetricRequest",
            "get": "GetCustomMetricRequest",
            "list": "ListCustomMetricsRequest",
            "update": "UpdateCustomMetricRequest",
            "archive": "ArchiveCustomMetricRequest",
        },
        request_resource_field="custom_metric",
        risk_gate=None,
        fields=(
            FieldSpec(
                "name",
                "string",
                writable_on_create=False,
                writable_on_update=False,
                output_only=True,
            ),
            FieldSpec(
                "parameter_name",
                "string",
                required_on_create=True,
                writable_on_update=False,
                immutable=True,
            ),
            FieldSpec("display_name", "string", required_on_create=True),
            FieldSpec("description", "string"),
            FieldSpec(
                "measurement_unit",
                "enum",
                required_on_create=True,
                writable_on_update=False,
                immutable=True,
            ),
            FieldSpec(
                "scope",
                "enum",
                required_on_create=True,
                writable_on_update=False,
                immutable=True,
                enum_values=("EVENT",),
            ),
            FieldSpec("restricted_metric_type", "enum[]"),
        ),
    ),
    ResourceSpec(
        name="KeyEvent",
        api_channel="beta",
        message_class="KeyEvent",
        parent_kind="property",
        collection_segment="keyEvents",
        actions=("create", "get", "list", "update", "delete"),
        methods={
            "create": "create_key_event",
            "get": "get_key_event",
            "list": "list_key_events",
            "update": "update_key_event",
            "delete": "delete_key_event",
        },
        request_classes={
            "create": "CreateKeyEventRequest",
            "get": "GetKeyEventRequest",
            "list": "ListKeyEventsRequest",
            "update": "UpdateKeyEventRequest",
            "delete": "DeleteKeyEventRequest",
        },
        request_resource_field="key_event",
        risk_gate="key_event",
        fields=(
            FieldSpec(
                "name",
                "string",
                writable_on_create=False,
                writable_on_update=False,
                output_only=True,
            ),
            FieldSpec(
                "event_name",
                "string",
                required_on_create=True,
                writable_on_update=False,
                immutable=True,
            ),
            FieldSpec("counting_method", "enum"),
            FieldSpec("default_value", "message"),
        ),
    ),
    ResourceSpec(
        name="DataStream",
        api_channel="beta",
        message_class="DataStream",
        parent_kind="property",
        collection_segment="dataStreams",
        actions=("create", "get", "list", "update", "delete"),
        methods={
            "create": "create_data_stream",
            "get": "get_data_stream",
            "list": "list_data_streams",
            "update": "update_data_stream",
            "delete": "delete_data_stream",
        },
        request_classes={
            "create": "CreateDataStreamRequest",
            "get": "GetDataStreamRequest",
            "list": "ListDataStreamsRequest",
            "update": "UpdateDataStreamRequest",
            "delete": "DeleteDataStreamRequest",
        },
        request_resource_field="data_stream",
        risk_gate="data_stream",
        aliases={"type": "type_"},
        fields=(
            FieldSpec(
                "name",
                "string",
                writable_on_create=False,
                writable_on_update=False,
                output_only=True,
            ),
            FieldSpec(
                "type",
                "enum",
                required_on_create=True,
                writable_on_update=False,
                immutable=True,
                enum_values=(
                    "WEB_DATA_STREAM",
                    "ANDROID_APP_DATA_STREAM",
                    "IOS_APP_DATA_STREAM",
                ),
            ),
            FieldSpec("display_name", "string", required_on_create=True),
            FieldSpec(
                "web_stream_data",
                "message",
                writable_on_update=False,
                immutable=True,
            ),
            FieldSpec(
                "android_app_stream_data",
                "message",
                writable_on_update=False,
                immutable=True,
            ),
            FieldSpec(
                "ios_app_stream_data",
                "message",
                writable_on_update=False,
                immutable=True,
            ),
        ),
    ),
    ResourceSpec(
        name="MeasurementProtocolSecret",
        api_channel="beta",
        message_class="MeasurementProtocolSecret",
        parent_kind="data_stream",
        collection_segment="measurementProtocolSecrets",
        actions=("create", "get", "list", "update", "delete"),
        methods={
            "create": "create_measurement_protocol_secret",
            "get": "get_measurement_protocol_secret",
            "list": "list_measurement_protocol_secrets",
            "update": "update_measurement_protocol_secret",
            "delete": "delete_measurement_protocol_secret",
        },
        request_classes={
            "create": "CreateMeasurementProtocolSecretRequest",
            "get": "GetMeasurementProtocolSecretRequest",
            "list": "ListMeasurementProtocolSecretsRequest",
            "update": "UpdateMeasurementProtocolSecretRequest",
            "delete": "DeleteMeasurementProtocolSecretRequest",
        },
        request_resource_field="measurement_protocol_secret",
        risk_gate="measurement_protocol_secret",
        fields=(
            FieldSpec(
                "name",
                "string",
                writable_on_create=False,
                writable_on_update=False,
                output_only=True,
            ),
            FieldSpec("display_name", "string", required_on_create=True),
            FieldSpec(
                "secret_value",
                "string",
                writable_on_create=False,
                writable_on_update=False,
                output_only=True,
            ),
        ),
    ),
    ResourceSpec(
        name="GoogleAdsLink",
        api_channel="beta",
        message_class="GoogleAdsLink",
        parent_kind="property",
        collection_segment="googleAdsLinks",
        actions=("create", "list", "update", "delete"),
        methods={
            "create": "create_google_ads_link",
            "list": "list_google_ads_links",
            "update": "update_google_ads_link",
            "delete": "delete_google_ads_link",
        },
        request_classes={
            "create": "CreateGoogleAdsLinkRequest",
            "list": "ListGoogleAdsLinksRequest",
            "update": "UpdateGoogleAdsLinkRequest",
            "delete": "DeleteGoogleAdsLinkRequest",
        },
        request_resource_field="google_ads_link",
        risk_gate="link",
        fields=(
            FieldSpec(
                "name",
                "string",
                writable_on_create=False,
                writable_on_update=False,
                output_only=True,
            ),
            FieldSpec(
                "customer_id",
                "string",
                required_on_create=True,
                writable_on_update=False,
                immutable=True,
            ),
            FieldSpec("ads_personalization_enabled", "bool"),
            FieldSpec("campaign_data_sharing_enabled", "bool"),
            FieldSpec("cost_data_sharing_enabled", "bool"),
        ),
    ),
    ResourceSpec(
        name="DataRetentionSettings",
        api_channel="beta",
        message_class="DataRetentionSettings",
        parent_kind="property",
        collection_segment="",
        singleton_suffix="dataRetentionSettings",
        actions=("get", "update"),
        methods={
            "get": "get_data_retention_settings",
            "update": "update_data_retention_settings",
        },
        request_classes={
            "get": "GetDataRetentionSettingsRequest",
            "update": "UpdateDataRetentionSettingsRequest",
        },
        request_resource_field="data_retention_settings",
        risk_gate="retention",
        fields=(
            FieldSpec(
                "name",
                "string",
                writable_on_create=False,
                writable_on_update=False,
                output_only=True,
            ),
            FieldSpec("event_data_retention", "enum"),
            FieldSpec("reset_user_data_on_new_activity", "bool"),
        ),
    ),
    ResourceSpec(
        name="AttributionSettings",
        api_channel="alpha",
        message_class="AttributionSettings",
        parent_kind="property",
        collection_segment="",
        singleton_suffix="attributionSettings",
        actions=("get", "update"),
        methods={
            "get": "get_attribution_settings",
            "update": "update_attribution_settings",
        },
        request_classes={
            "get": "GetAttributionSettingsRequest",
            "update": "UpdateAttributionSettingsRequest",
        },
        request_resource_field="attribution_settings",
        risk_gate="attribution",
        fields=(
            FieldSpec(
                "name",
                "string",
                writable_on_create=False,
                writable_on_update=False,
                output_only=True,
            ),
            FieldSpec("acquisition_conversion_event_lookback_window", "enum"),
            FieldSpec("other_conversion_event_lookback_window", "enum"),
            FieldSpec("reporting_attribution_model", "enum"),
            FieldSpec("ads_web_conversion_data_export_scope", "enum"),
        ),
    ),
)

_REGISTRY = {item.name: item for item in _RESOURCE_SPECS}


def list_resource_specs() -> Iterable[ResourceSpec]:
    """Returns all registered resources in stable order."""
    return _RESOURCE_SPECS


def get_resource_spec(resource: str) -> ResourceSpec:
    """Returns a resource spec or raises a clear error."""
    try:
        return _REGISTRY[resource]
    except KeyError as exc:
        supported = ", ".join(_REGISTRY)
        raise ValueError(
            f"Unsupported resource '{resource}'. Supported: {supported}."
        ) from exc

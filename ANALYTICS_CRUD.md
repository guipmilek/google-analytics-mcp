# Protected Google Analytics Admin CRUD

This fork adds a guarded CRUD layer to the existing read-only Analytics MCP.
The tools use the Google Analytics Admin API and preserve the existing Data API
reporting tools.

## Tools

- `analytics_list_mutable_resources`
- `analytics_get_mutation_schema`
- `analytics_get_resource`
- `analytics_list_resources`
- `analytics_create_resource`
- `analytics_update_resource`
- `analytics_archive_resource`
- `analytics_delete_resource`
- `analytics_batch_operations`

Supported resources:

- `CustomDimension`
- `CustomMetric`
- `KeyEvent`
- `DataStream`
- `MeasurementProtocolSecret`
- `GoogleAdsLink`
- `DataRetentionSettings`
- `AttributionSettings` (Alpha, disabled by default)

## Validation model

The Google Analytics Admin API does not expose a generic `validate_only`
parameter comparable to Google Ads. In this connector, `validate_only=true`
means a strict local preflight:

1. allowlist and risk-gate validation;
2. resource schema and field validation;
3. enum and SDK request-object construction;
4. current-resource or parent-collection read;
5. precondition snapshot hashing;
6. normalized operation hashing;
7. signed HMAC confirmation issuance.

No Admin API mutation is sent during this preflight. The response explicitly
reports:

```json
{
  "mode": "VALIDATE_ONLY",
  "validation_kind": "CONNECTOR_PREFLIGHT",
  "admin_api_validate_only_supported": false,
  "execution_attempted": false,
  "executed": false
}
```

Execution repeats the precondition reads. Any concurrent change alters the
normalized payload hash and invalidates the confirmation.

## Non-atomic batches

Admin API resources use separate RPC methods. Mixed batches are therefore not
atomic. The connector executes sequentially and stops on the first failed or
unknown operation:

```json
{
  "atomic": false,
  "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR"
}
```

Completed operations are never described as rolled back. A transport failure
after dispatch is reported as potentially completed and is not automatically
retried.

## Environment

Start with all mutation gates disabled:

```env
GOOGLE_ANALYTICS_ADMIN_MUTATIONS_ENABLED=false
GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS=401804063
GOOGLE_ANALYTICS_ALLOWED_PROPERTY_IDS=546475155
GOOGLE_ANALYTICS_ALLOWED_DATA_STREAM_IDS=15297504355
GOOGLE_ANALYTICS_MAX_OPERATIONS_PER_REQUEST=10

GOOGLE_ANALYTICS_CONFIRMATION_SECRET=<random secret of at least 32 bytes>
GOOGLE_ANALYTICS_CONFIRMATION_TTL_SECONDS=900

GOOGLE_ANALYTICS_ALLOW_DELETE=false
GOOGLE_ANALYTICS_ALLOW_ARCHIVE=false
GOOGLE_ANALYTICS_ALLOW_PROPERTY_UPDATE=false
GOOGLE_ANALYTICS_ALLOW_DATA_STREAM_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_KEY_EVENT_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_RETENTION_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_ATTRIBUTION_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_LINK_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_MEASUREMENT_PROTOCOL_SECRET_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_ALPHA_RESOURCES=false
```

The confirmation secret must be configured directly in the deployment
platform. Do not reuse the Google Ads confirmation secret.

## OAuth scope

Read-only tools continue to request:

```text
https://www.googleapis.com/auth/analytics.readonly
```

Mutation execution requests:

```text
https://www.googleapis.com/auth/analytics.edit
```

The authenticated user or service account must also have sufficient access to
the target Analytics property.

## Example

Validate a custom dimension creation:

```json
{
  "property_id": "546475155",
  "resource": "CustomDimension",
  "data": {
    "parameter_name": "lead_type",
    "display_name": "Tipo de lead",
    "description": "Origem comercial do lead",
    "scope": "EVENT"
  },
  "validate_only": true
}
```

A successful validation returns a confirmation in the form:

```text
EXECUTE <32-character-operation-hash>.<signed-payload>.<signature>
```

Execution must resubmit the same operation data with `validate_only=false` and
the unexpired confirmation.

# Analytics Admin direct CRUD

The Horizon server exposes a single direct mutation contract:
`direct-crud-v1`.

## Behavior

- A write call validates and executes in one MCP invocation.
- `dry_run=false` is the default.
- `dry_run=true` performs scope, schema, request-building, snapshot, and
  precondition reads without sending a Google Admin API mutation.
- Batches are non-atomic and use `SEQUENTIAL_STOP_ON_FIRST_ERROR`.
- Results distinguish known rejection, partial execution, and unknown
  execution state.
- Successful writes are read back. Verification failure is reported without
  pretending that the dispatched mutation did not occur.
- Deleting an already absent resource succeeds as `ALREADY_ABSENT`.

The Analytics Admin API has no generic native validate-only mode. `dry_run`
therefore represents connector-side validation only.

## Supported resources

| Resource | Actions |
|---|---|
| `CustomDimension` | create, get, list, update, archive |
| `CustomMetric` | create, get, list, update, archive |
| `KeyEvent` | create, get, list, update, delete |
| `DataStream` | create, get, list, update, delete |
| `MeasurementProtocolSecret` | create, get, list, update, delete |
| `GoogleAdsLink` | create, list, update, delete |
| `DataRetentionSettings` | get, update |
| `AttributionSettings` | get, update |

Use `analytics_get_mutation_schema` for exact fields, aliases, required create
fields, immutable fields, and update-mask rules.

## Horizon deployment: at most two keys

```env
MCP_CREDENTIALS=<base64-encoded {"google_credentials":{...}}>
# Optional restriction:
MCP_CONFIG={"accounts":["401804063"],"properties":["546475155"],"data_streams":[],"ads_customers":[],"max_operations":10}
```

`MCP_CONFIG` is optional. Missing or empty allowlists allow every resource
accessible to the credential; configured non-empty arrays restrict their
corresponding resource type. The default batch limit is 10. Cross-property
references are still rejected.

The old `GOOGLE_APPLICATION_CREDENTIALS_JSON_BASE64` and variables beginning
with
`GOOGLE_ANALYTICS_ADMIN_MUTATIONS_ENABLED`,
`GOOGLE_ANALYTICS_ALLOWED_`, `GOOGLE_ANALYTICS_MAX_`,
`GOOGLE_ANALYTICS_ALLOW_`, or `GOOGLE_ANALYTICS_CONFIRMATION_` are not used by
the Horizon direct-CRUD runtime and should be removed from the deployment.

## MCP action annotations

Read tools are annotated read-only and idempotent. Delete is annotated
destructive and idempotent. Archive, update, and mixed batches are annotated
destructive. All Google API tools are open-world.

These annotations must be imported into the MCP client. In ChatGPT, refresh the
custom app after deployment, then enable the actions under Workspace Settings
→ Apps → Action control. A workspace owner/admin may choose **Never ask** where
the workspace supports it. The server cannot override a ChatGPT
`workspace_policy_block`.

## Verification

Use a dedicated non-production Analytics account and property for live CRUD.
The repository test suite mocks Google clients and is safe to run locally:

```shell
python -m unittest discover -s tests -p "*_test.py"
python -m compileall analytics_mcp horizon_server.py
fastmcp inspect horizon_server.py:mcp
```

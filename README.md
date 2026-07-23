# Google Analytics MCP Server

Google Analytics Admin API and Data API MCP with a native Prefect
Horizon/FastMCP entrypoint.

## Tools

Account, property, and reporting tools:

- `get_account_summaries`
- `get_property_details`
- `list_google_ads_links`
- `list_property_annotations`
- `run_report`
- `run_realtime_report`
- `run_funnel_report`
- `run_conversions_report`
- `get_custom_dimensions_and_metrics`

Direct Admin API CRUD:

- `analytics_crud_status`
- `analytics_list_mutable_resources`
- `analytics_get_mutation_schema`
- `analytics_get_resource`
- `analytics_list_resources`
- `analytics_create_resource`
- `analytics_update_resource`
- `analytics_archive_resource`
- `analytics_delete_resource`
- `analytics_batch_operations`

The CRUD facade supports custom dimensions, custom metrics, key events, data
streams, Measurement Protocol secrets, Google Ads links, data retention, and
attribution settings.

Writes use the `direct-crud-v1` contract. Each call validates its scope and
schema, captures precondition snapshots, executes immediately unless
`dry_run=true`, and performs post-write reads. Delete is idempotent for an
already absent resource. Batches are non-atomic and stop at the first error.

There are no connector-level mutation switches, per-action gates, signed
confirmations, approval codes, or prepare/execute pairs. Account, property,
optional data-stream, and Google Ads customer allowlists remain enforced.

See [ANALYTICS_CRUD.md](ANALYTICS_CRUD.md) for resource schemas, configuration,
and ChatGPT workspace setup.

## Horizon deployment

```text
Entrypoint: horizon_server.py:mcp
Runtime: Python 3.12
Contract: direct-crud-v1
```

Required credentials:

```env
GOOGLE_APPLICATION_CREDENTIALS_JSON_BASE64=<base64-service-account-json>
GOOGLE_PROJECT_ID=<google-cloud-project-id>
GOOGLE_CLOUD_PROJECT=<google-cloud-project-id>
```

Required write scope:

```env
GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS=<comma-separated-numeric-ids>
GOOGLE_ANALYTICS_ALLOWED_PROPERTY_IDS=<comma-separated-numeric-ids>
GOOGLE_ANALYTICS_ALLOWED_DATA_STREAM_IDS=<optional-comma-separated-ids>
GOOGLE_ANALYTICS_ALLOWED_GOOGLE_ADS_CUSTOMER_IDS=<optional-comma-separated-ids>
GOOGLE_ANALYTICS_MAX_OPERATIONS_PER_REQUEST=10
```

Empty account or property allowlists fail closed for writes.

## ChatGPT workspace setup

After redeploying, refresh the custom MCP app as a ChatGPT workspace owner or
admin. Enable its write actions in Workspace Settings → Apps → Action control.
Where workspace policy permits, select **Never ask**. A
`workspace_policy_block` is enforced by ChatGPT and cannot be bypassed by
server code.

## Local verification

```shell
pip install -e ".[dev]"
python -m compileall analytics_mcp horizon_server.py
python -m unittest discover -s tests -p "*_test.py"
fastmcp inspect horizon_server.py:mcp
```

The automated tests use mocks and do not access a real Analytics property.
Run live CRUD only against dedicated non-production account/property assets.

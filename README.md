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

Horizon uses exactly two deployment keys:

```env
MCP_CREDENTIALS=<base64-encoded credential envelope>
MCP_CONFIG={"accounts":["401804063"],"properties":["546475155"],"data_streams":[],"ads_customers":[],"max_operations":10}
```

The decoded credential envelope has one field:

```json
{"google_credentials":{"type":"service_account","project_id":"..."}}
```

Empty account or property allowlists fail closed for writes.
`data_streams` and `ads_customers` may remain empty until those resource types
are mutated. The old per-setting Horizon variables should be removed.

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

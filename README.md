# Google Analytics MCP Server (Experimental)

This repository contains an MCP server for the Google Analytics Admin API and
Data API. This fork also includes a protected administrative CRUD facade and a
native Prefect Horizon/FastMCP entrypoint.

## Tools

### Account and property information

- `get_account_summaries`
- `get_property_details`
- `list_google_ads_links`
- `list_property_annotations`

### Reporting

- `run_report`
- `run_realtime_report`
- `run_funnel_report`
- `run_conversions_report`
- `get_custom_dimensions_and_metrics`

### Protected Admin API

Read-only inspection:

- `analytics_safety_status`
- `analytics_confirmation_diagnostics`
- `analytics_list_mutable_resources`
- `analytics_get_mutation_schema`
- `analytics_get_resource`
- `analytics_list_resources`

Protected mutations:

- `analytics_create_resource`
- `analytics_update_resource`
- `analytics_archive_resource`
- `analytics_delete_resource`
- `analytics_batch_operations`

The mutation facade supports custom dimensions, custom metrics, key events,
data streams, Measurement Protocol secrets, Google Ads links, data retention,
and attribution settings.

See [ANALYTICS_CRUD.md](ANALYTICS_CRUD.md) for the complete safety model,
environment variables, allowlists, confirmation format, key rotation, and
Horizon deployment instructions.

## Mutation safety summary

The deployment is fail-closed by default.

A mutation requires:

1. `GOOGLE_ANALYTICS_ADMIN_MUTATIONS_ENABLED=true`;
2. the relevant action gate, such as `GOOGLE_ANALYTICS_ALLOW_UPDATE=true`;
3. the resource-specific gate;
4. account and property allowlist approval;
5. stream or Google Ads customer allowlist approval when applicable;
6. `validate_only=true` connector preflight;
7. the unexpired HMAC confirmation returned by that exact preflight.

`validate_only=true` is a connector preflight. The Google Analytics Admin API
does not expose a generic native validate-only mutation mode.

Batches are:

```json
{
  "atomic": false,
  "execution_strategy": "SEQUENTIAL_STOP_ON_FIRST_ERROR"
}
```

Replay and cross-instance behavior is:

```json
{
  "cross_instance_valid": null,
  "cross_instance_requirement": "MATCHING_CONFIRMATION_KEY_ID",
  "replay_protection": "BEST_EFFORT_PROCESS_LOCAL",
  "globally_single_use": false
}
```

`analytics_safety_status` and `analytics_confirmation_diagnostics` are
read-only. They expose only non-secret key and process identifiers, never the
confirmation secret, ADC JSON, OAuth credentials, access tokens, or synthetic
confirmation tokens.

## Horizon deployment

Use:

```text
horizon_server.py:mcp
```

Required credential secret:

```env
GOOGLE_APPLICATION_CREDENTIALS_JSON_BASE64=<base64 service-account JSON>
```

Protected mutation and confirmation-key configuration is documented in
[ANALYTICS_CRUD.md](ANALYTICS_CRUD.md).

## Local setup

Python 3.10 or newer is required.

Install with the development dependencies:

```shell
pip install -e ".[dev]"
```

Enable the following Google Cloud APIs:

- Google Analytics Admin API
- Google Analytics Data API

Configure Application Default Credentials with the read-only scope for reports
and the edit scope only when protected mutation execution is required:

```text
https://www.googleapis.com/auth/analytics.readonly
https://www.googleapis.com/auth/analytics.edit
```

## Gemini configuration

Example:

```json
{
  "mcpServers": {
    "analytics-mcp": {
      "command": "pipx",
      "args": ["run", "analytics-mcp"],
      "env": {
        "GOOGLE_APPLICATION_CREDENTIALS": "PATH_TO_CREDENTIALS_JSON",
        "GOOGLE_PROJECT_ID": "YOUR_PROJECT_ID"
      }
    }
  }
}
```

## Claude Code configuration

```shell
claude mcp add analytics-mcp \
  --scope user \
  -e "GOOGLE_APPLICATION_CREDENTIALS=PATH_TO_CREDENTIALS_JSON" \
  -e "GOOGLE_PROJECT_ID=YOUR_PROJECT_ID" \
  -- pipx run analytics-mcp
```

## Validation

Recommended checks before merging:

```shell
python -m compileall analytics_mcp horizon_server.py
python -m unittest discover -s tests -p "*_test.py"
black --check -l 80 analytics_mcp tests horizon_server.py
fastmcp inspect horizon_server.py:mcp
```

The tests use mocks and must not access a real Google Analytics property.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

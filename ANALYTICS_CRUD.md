# Protected Google Analytics Admin CRUD

This fork adds a guarded CRUD layer to the existing read-only Analytics MCP.
The tools use the Google Analytics Admin API and preserve the existing Data API
reporting tools.

The initial protected deployment scope is the Poli Steel Analytics account
`401804063`, property `546475155`, web stream `15297504355`, and Google Ads
customer `8448275903`. These numeric identifiers are allowlist values, not
credentials or secrets.

## Tools

Read-only safety and schema tools:

- `analytics_safety_status`
- `analytics_confirmation_diagnostics`
- `analytics_list_mutable_resources`
- `analytics_get_mutation_schema`
- `analytics_get_resource`
- `analytics_list_resources`

Protected mutation tools:

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

## Safety status and confirmation diagnostics

`analytics_safety_status` is read-only and does not call Google Analytics APIs,
run preflight, issue confirmations, or compute operation hashes. It reloads the
environment on every call and reports:

- global mutation state;
- general action gates;
- resource-specific gates;
- account, property, stream, and Google Ads customer allowlists;
- batch limit and confirmation TTL;
- whether current and previous confirmation secrets are configured and valid;
- non-secret confirmation key identifiers;
- the current process instance identifier;
- hash, token, replay, and cross-instance requirements;
- non-atomic sequential execution semantics.

The tool never returns the confirmation secret, ADC JSON, OAuth secrets, access
tokens, or confirmation tokens.

`analytics_confirmation_diagnostics` performs a synthetic issue/verify round
trip entirely inside the current process. It does not return the generated
confirmation, register replay state, call Google APIs, run a production
preflight, or mutate resources. Use its `confirmation_key_id` and
`process_instance_id` values to detect inconsistent replicas or revisions.

The diagnostics distinguish:

- `CONFIRMATION_KEY_MISMATCH`: the receipt declares a key ID that is neither the
  configured current key nor the valid previous rotation key;
- `INVALID_CONFIRMATION`: the signature is invalid for the key ID declared by
  the receipt, indicating corruption or alteration;
- `CONFIRMATION_EXPIRED`: the receipt TTL elapsed;
- `CONFIRMATION_REPLAYED`: the receipt was already registered in the current
  process.

## Validation model

The Google Analytics Admin API does not expose a generic `validate_only`
parameter comparable to Google Ads. In this connector, `validate_only=true`
means a strict local preflight:

1. global, action, and resource risk-gate validation;
2. account, property, data-stream, and Google Ads customer allowlist validation;
3. property parent-account read and precondition binding;
4. resource schema and field validation;
5. enum and SDK request-object construction;
6. current-resource or parent-collection read;
7. precondition snapshot hashing;
8. normalized operation hashing;
9. signed HMAC confirmation issuance.

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

Execution repeats property-parent and resource precondition reads. A concurrent
change alters the signed payload and invalidates the confirmation.

Confirmations use:

```text
EXECUTE <32-character-operation-hash>.<signed-payload>.<signature>
```

Version-2 confirmations include a non-secret `kid` key identifier and `iid`
issuing-process identifier in the signed payload. The verifier accepts the
current key or an explicitly configured valid previous key during controlled
rotation. Version-1 receipts remain compatible while unexpired.

Cross-instance validity is not asserted unconditionally. It requires matching
confirmation key IDs across the issuing and verifying instances:

```json
{
  "cross_instance_valid": null,
  "cross_instance_requirement": "MATCHING_CONFIRMATION_KEY_ID",
  "replay_protection": "BEST_EFFORT_PROCESS_LOCAL",
  "globally_single_use": false
}
```

Receipts issued before a redeploy, key change, or safety-model change must be
revalidated unless the old key is deliberately configured as the previous key
for a bounded rotation window.

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

A failed read after a successful mutation is reported separately as
`SUCCEEDED_WITH_VERIFICATION_WARNINGS`; it does not rewrite the known mutation
dispatch result as an unknown execution.

## Horizon deployment

Use this server entrypoint in Prefect Horizon:

```text
horizon_server.py:mcp
```

The entrypoint exposes the existing read and CRUD functions through a native
FastMCP server. It does not proxy through a second subprocess.

For ADC credentials stored as a Horizon secret, configure:

```env
GOOGLE_APPLICATION_CREDENTIALS_JSON_BASE64=<base64 service-account JSON>
```

The entrypoint decodes the value into a mode `0600` file under `/tmp` and sets
`GOOGLE_APPLICATION_CREDENTIALS`. Existing ADC mechanisms remain supported when
the base64 variable is absent.

Optional Google OAuth protection for the public MCP endpoint uses:

```env
GOOGLE_ANALYTICS_MCP_OAUTH_CLIENT_ID=<client ID>
GOOGLE_ANALYTICS_MCP_OAUTH_CLIENT_SECRET=<client secret>
GOOGLE_ANALYTICS_MCP_BASE_URL=https://<project>.fastmcp.app
```

The OAuth client ID and secret must be configured together. API calls still use
ADC; endpoint login and Google Analytics API authorization are separate layers.

## Environment

All gates default to `false`, all allowlists default to empty, the batch limit
defaults to `10`, and the confirmation TTL defaults to `900` seconds.

Fail-closed example:

```env
GOOGLE_ANALYTICS_ADMIN_MUTATIONS_ENABLED=false

GOOGLE_ANALYTICS_ALLOW_CREATE=false
GOOGLE_ANALYTICS_ALLOW_UPDATE=false
GOOGLE_ANALYTICS_ALLOW_DELETE=false
GOOGLE_ANALYTICS_ALLOW_ARCHIVE=false

GOOGLE_ANALYTICS_ALLOW_PROPERTY_UPDATE=false
GOOGLE_ANALYTICS_ALLOW_DATA_STREAM_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_KEY_EVENT_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_CUSTOM_DIMENSION_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_CUSTOM_METRIC_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_RETENTION_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_ATTRIBUTION_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_LINK_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_MEASUREMENT_PROTOCOL_SECRET_CHANGES=false
GOOGLE_ANALYTICS_ALLOW_ALPHA_RESOURCES=false

GOOGLE_ANALYTICS_ALLOWED_ACCOUNT_IDS=401804063
GOOGLE_ANALYTICS_ALLOWED_PROPERTY_IDS=546475155
GOOGLE_ANALYTICS_ALLOWED_DATA_STREAM_IDS=15297504355
GOOGLE_ANALYTICS_ALLOWED_GOOGLE_ADS_CUSTOMER_IDS=8448275903

GOOGLE_ANALYTICS_MAX_OPERATIONS_PER_REQUEST=10
GOOGLE_ANALYTICS_CONFIRMATION_TTL_SECONDS=900
GOOGLE_ANALYTICS_CONFIRMATION_SECRET=<random secret of at least 32 bytes>
# Optional only during controlled key rotation:
GOOGLE_ANALYTICS_CONFIRMATION_PREVIOUS_SECRET=<previous secret>
```

To enable a mutation, the global gate, the action gate, and the applicable
resource gate must all be enabled. For example, creating a custom dimension
requires:

```text
GOOGLE_ANALYTICS_ADMIN_MUTATIONS_ENABLED=true
GOOGLE_ANALYTICS_ALLOW_CREATE=true
GOOGLE_ANALYTICS_ALLOW_CUSTOM_DIMENSION_CHANGES=true
```

A `GoogleAdsLink` create, update, or delete also requires its customer ID in
`GOOGLE_ANALYTICS_ALLOWED_GOOGLE_ADS_CUSTOMER_IDS`. Existing links outside the
allowlist remain readable but cannot be mutated.

The current confirmation secret must be configured directly in the deployment
platform and must be identical across every active replica and revision. Do not
reuse the Google Ads confirmation secret.

For controlled rotation:

1. deploy the new value as `GOOGLE_ANALYTICS_CONFIRMATION_SECRET` everywhere;
2. temporarily configure the old value as
   `GOOGLE_ANALYTICS_CONFIRMATION_PREVIOUS_SECRET` everywhere;
3. verify matching key IDs with `analytics_confirmation_diagnostics`;
4. wait for all receipts issued under the old key to expire;
5. remove `GOOGLE_ANALYTICS_CONFIRMATION_PREVIOUS_SECRET`.

Do not leave a previous secret configured indefinitely.

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

A successful validation returns an unexpired signed confirmation. Execution
must resubmit the exact same operation data with `validate_only=false` and that
confirmation.

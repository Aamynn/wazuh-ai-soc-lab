# Live Wazuh integration plan

**Planned, not deployed or end-to-end tested.** Do not point a production environment at this starter as though it were a deployed collector.

## 1. Reproducible isolated lab

Use the official Wazuh deployment instructions for the selected supported release. Pin compatible server/indexer/dashboard/agent versions and record Linux distribution, CPU architecture, RAM, disk, and container or VM settings. Current deployment guidance is authoritative; the historical PDF is not an installation script.

- [Architecture](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)

Start with one Linux agent. Add a Windows VM when testing Windows events. Containerized Linux agents do not substitute for Windows telemetry. Keep administrative interfaces restricted and use the documented certificates/authentication. Never commit enrollment keys, generated certificates, passwords, or live logs.

## 2. Telemetry contract

The current CLI consumes normalized JSONL, **not raw Wazuh alert JSON**. Build a mapper from real, sanitized fixtures from your selected version. Preserve source index and document identifiers in a separate provenance mapping. Do not invent rule IDs or assume that all SSH events are indexed in the default alert stream.

In particular, a failed-logins-to-success correlation needs both failure and success telemetry. Verify alert thresholds and collection/archive settings. Enabling all-event archives has storage and privacy consequences; define retention before doing it.

| Normalized field | Mapping decision to validate |
| --- | --- |
| id | Stable collision-resistant key derived from source index + document ID |
| timestamp | UTC event time with timezone, not a formatted dashboard label |
| host | Stable agent identity, resolving display-name changes |
| user | Account field verified for the selected SSH decoder |
| source_ip | Parsed source address from that decoder |
| event_type | Explicit mapping of tested failure/success records |

Missing mandatory fields must be counted and quarantined; do not silently infer them with an LLM.

## 3. Collector or custom integration

For indexer polling, use a restricted read-only identity, bounded time windows, persistent cursor/tie-breaker, overlap for delayed events, deduplication, and durable jobs before advancing checkpoints. Agent management uses the manager API; indexed event searches use the indexer API.

An alternative is a Wazuh custom integration that quickly enqueues alerts. Do not block Wazuh detection while waiting for inference. Exclude any analysis-output index from input to prevent feedback loops.

- [Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html)
- [Custom integrations](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)

## 4. Validation gates

1. Observe a controlled failure and success with correct fields on the endpoint.
2. Confirm receipt and indexing, and document end-to-end delay.
3. Export a sanitized fixture and verify the mapper's normalized output.
4. Replay it through this CLI and compare expected evidence.
5. Restart the collector mid-batch: no lost jobs; duplicate deliveries do not duplicate final writes.
6. Disconnect the model: collection continues and analysis records a fallback.
7. Use `wazuh-logtest` for Wazuh decoder/rule changes, then run end-to-end checks separately.

The Python LAB-SSH-001 rule is not a Wazuh XML rule and is not tested by `wazuh-logtest`. A future Wazuh rule must be validated independently.

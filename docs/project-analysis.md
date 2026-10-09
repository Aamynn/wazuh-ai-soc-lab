# From the original study to a personal engineering project

## Historical scope

The 2020 report describes a single-host Wazuh + ELK installation, endpoint enrollment, log search, dashboards, file/registry monitoring, configuration auditing, MITRE ATT&CK views, and an active-response example. It also presents a conceptual seven-module SIEM architecture. The original code/configuration was not available for this reconstruction.

The strongest evidence in the report concerns installation and feature presentation. Screenshots do not establish end-to-end detection coverage, false-positive rates, incident response effectiveness, or production readiness. Those require repeatable tests and measured outcomes.

## Design decisions

| Decision | Reason |
| --- | --- |
| Start with one complete SSH scenario | Establish a tested data-to-investigation path before broadening scope |
| Deterministic baseline by default | Make behavior reproducible and distinguish correlation from AI |
| Optional local inference | Avoid requiring credentials or sending lab evidence to a hosted provider |
| Keep human review mandatory | A successful login after failures is ambiguous |
| Use synthetic events | Publish reproducible examples without organizational telemetry |
| Defer clustering | Validate correctness before deployment complexity |
| Retain source references | Make explanations inspectable, while acknowledging that citations alone do not prove truth |

## Improvements to the historical design

1. Rebuild with supported and mutually compatible components. The report's Ubuntu 16.04/Wazuh 3.x setup is historical, not the deployment target.
2. Document an actual deployed architecture separately from a proposed functional diagram.
3. Replace installation screenshots with versioned configuration and tested setup procedures.
4. Add positive and benign controls to each detection, and record collection prerequisites.
5. Monitor missing telemetry, ingestion delay, agent disconnection, and storage retention.
6. Add incident disposition, evidence links, and a review trail instead of equating alerts with incidents.
7. Restrict response actions by explicit policy; do not trigger broad remediation from generic severity alone.

Technical documentation corrections: Kibana's historical port 5601 served its web interface, not Elasticsearch cluster communication; live dashboards query stored/indexed data rather than directly polling every endpoint. A blank policy view does not prove all checks ran. XML examples must have matching tags and be validated against the selected release.

Current Wazuh describes agents plus server, indexer, and dashboard. Current Elastic Security also has a detection engine, so a blanket statement that Elastic cannot alert or provide SIEM functionality is not suitable for the new documentation.

## Portfolio evidence to add

- Rebuild transcript on a fresh environment, with versions and hardware.
- One scenario recording showing input, detection, timeline, explanation, and analyst disposition.
- Measured ingestion and analysis latency; no invented benchmark percentages.
- A short statement of personal contribution and historical attribution.

## Primary references

- https://documentation.wazuh.com/current/getting-started/architecture.html
- https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
- https://www.elastic.co/docs/solutions/security/detect-and-alert

References reviewed on 2026-10-09. Verify compatibility again when implementing the live deployment.

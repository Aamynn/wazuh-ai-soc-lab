# Implementation roadmap

## 0.1 — Runnable starter

- [x] Synthetic normalized SSH fixtures and documented input schema.
- [x] Deterministic sequence correlation with evidence timeline.
- [x] Optional local Ollama adapter, bounded context, reference validation, fallback.
- [x] Automated functional tests and CI workflow.
- [x] Original-study analysis, attribution, and limitations.

## 0.2 — Live Linux/Wazuh lab

- [ ] Pin and record a supported Wazuh component set and isolated lab resources.
- [ ] Deploy one Linux endpoint and capture sanitized failure/success fixtures.
- [ ] Implement a versioned Wazuh-to-normalized-event mapper.
- [ ] Implement read-only collector, durable queue/checkpoints, and idempotent writes.
- [ ] Verify restart/replay behavior and telemetry completeness.

**Acceptance:** a fresh lab reproduces the documented sequence with traceable source events; stopping inference does not stop collection.

## 0.3 — Detection coverage

- [ ] Windows privileged-group membership changes.
- [ ] Defined suspicious PowerShell behavior with benign controls.
- [ ] Sensitive file modification.
- [ ] Defined web scanning behavior with benign controls.
- [ ] Test each Wazuh decoder/rule and the complete collection path.

**Acceptance:** every scenario has prerequisites, fixtures, expected outputs, false-positive notes, and an investigation runbook.

## 0.4 — Evaluated AI investigations

- [ ] Test a real locally installed model and record its exact identity/digest.
- [ ] Add reviewed runbook retrieval beyond the fixed SSH selection.
- [ ] Build a withheld, independently reviewed evaluation set.
- [ ] Measure groundedness, uncertainty, review time, latency, and adversarial behavior.
- [ ] Add incident disposition and a read-only analyst interface.

**Acceptance:** publish measured results and failure examples; no automatic remediation based on model output.

## Portfolio release

- [ ] Choose a license for the new implementation.
- [ ] Record a short end-to-end demonstration.
- [ ] Publish a tagged release with tested setup instructions and known limitations.
- [ ] Add resource and retention measurements before considering distributed deployment.

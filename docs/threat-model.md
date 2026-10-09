# AI boundary and limitations

## Assets and trust boundaries

Source events, account identifiers, hostnames, investigation conclusions, and model endpoints matter. Events are untrusted. The reviewed prompt/runbook and application code are trusted local configuration. Model output remains untrusted even if it matches the schema.

| Threat | Starter control | Remaining limitation |
| --- | --- | --- |
| Instructions in raw logs | Only six normalized fields are admitted; free-text raw messages are dropped | Identifier filtering is not a general prompt-injection defense |
| Invented evidence references | Reject IDs outside the supplied context | A real ID can still be cited for an unsupported claim |
| Unauthorized remediation | No executor or model tools; human review required | Humans must still critically inspect advice |
| Unexpected outbound endpoint | Fixed loopback URL, no proxies or redirects | A locally configured server may itself forward requests; use local-only models/configuration |
| Sensitive content | Synthetic fixtures, strict input projection, no raw-provider errors in output | Allowed identity fields can still be sensitive in real data |
| Excessive processing | Input/event/incident/evidence/output limits and request timeout | Per-read timeout is not a strict whole-job deadline against a malicious streaming server |
| Provider failure | Clearly labeled baseline fallback | Consumer must inspect provenance rather than assume AI succeeded |
| Unsafe future rendering | Output is JSON only | Future UIs must escape content and never execute suggestions |

The repository intentionally has no hosted API, authentication service, cloud credential storage, response automation, or live indexer access. Add a fresh security review when introducing any of them.

Tests cover input projection and reference rejection. They do not prove LLM resistance to adversarial prompts. Evaluate chosen models on withheld benign, ambiguous, malicious, and adversarial examples before operational use.

Reference: [OWASP LLM Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).

# Validation and evaluation

## Initial validation record — 2026-10-09

All 22 functional tests passed locally on Python 3.9.6 and in [GitHub Actions run 1](https://github.com/Aamynn/wazuh-ai-soc-lab/actions/runs/37970812079) on Python 3.9, 3.12, and 3.13 for commit `051fc8e8e0296c8991a19ecacab948e69765eaa2`. Both fixture commands passed in every CI job. Consult the workflow badge for later revisions. This verifies the implemented starter, not a live deployment or model quality.

## 0.2 validation

The expanded suite contains 36 tests, including randomized comparison against a reference correlation algorithm, JSON ambiguity rejection, output escaping, file preservation, interrupted model responses, and limit handling. CI also installs the package and runs it outside the checkout to verify packaged resources. No performance speedup percentage or real-model accuracy is claimed.

## Reproduce implementation checks

```bash
python3 -m unittest discover -s tests -v
python3 -m soc_lab --input sample-data/ssh-sequence.jsonl
python3 -m soc_lab --input sample-data/benign-logins.jsonl
```

The tests cover positive/benign fixtures, order, timezone normalization, time boundaries, entity separation, malformed input, duplicate IDs, input bounds, excluded free-text instructions/secrets, unknown evidence, mandatory review, mocked model output/failure, transport shape, and CLI behavior.

These are functional checks, not a measured detection or AI-quality benchmark. The sample data is deliberately small and synthetic. Ollama transport tests use mocks; no local model download, real inference, or live Wazuh collection was performed as part of creating the starter.

## Future evaluation set

Create independently labeled cases, with provenance and permission to distribute them. Include at least:

- Repeated failures then unauthorized success.
- Legitimate retries after a password change.
- Failures and success from different hosts/accounts/IPs.
- Timezone differences, delayed arrivals, and missing success events.
- Shared-NAT and service-account behavior.
- Malicious instructions embedded in permitted data surfaces.

Split prompt-development cases from final evaluation cases. Record model name/version/digest, prompt/runbook hashes, hardware, inference settings, and evaluation date. A developer's own judgment is not a substitute for independent review when measuring analyst benefit.

| Metric | Measurement |
| --- | --- |
| Detection precision | True positive investigations / all triggered investigations |
| Detection recall | Detected positive scenarios / all labeled positive scenarios |
| Supported claims | Reviewer-supported factual claims / all factual claims |
| Unsupported claims | Unsupported factual claims / all factual claims |
| Abstention quality | Correct handling of missing or ambiguous evidence |
| Investigation time | Compare baseline and AI-assisted review on equivalent cases |
| Runtime | Median and p95 latency, fallback rate, resource use |
| Adversarial outcomes | Observed failures by attack category, with examples |

Keep denominators, case definitions, sample sizes, and limitations alongside every reported metric. Never advertise a percentage derived from the two bundled fixtures as general accuracy.

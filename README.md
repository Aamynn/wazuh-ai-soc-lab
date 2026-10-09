# Wazuh AI SOC Lab

[![Tests](https://github.com/Aamynn/wazuh-ai-soc-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/Aamynn/wazuh-ai-soc-lab/actions/workflows/tests.yml)

A personal security engineering lab that turns SSH authentication events into investigations with traceable evidence and optional local AI analysis.

Inspired by a Wazuh + ELK SIEM study, the project explores detection engineering, alert triage, and AI-assisted investigation.

> **Current scope:** a working CLI prototype using synthetic events. Live Wazuh integration is planned; the local AI adapter has been tested with mocked responses, with real-model evaluation still pending.

## Features

- Detect repeated SSH failures followed by a successful login for the same host, account, and source IP.
- Produce a chronological evidence timeline and investigation guidance.
- Generate optional local AI explanations through Ollama.
- Validate evidence references and retain a deterministic analysis if AI fails.
- Run 22 automated tests, with CI covering Python 3.9, 3.12, and 3.13.

Investigations require human review. The application does not execute response actions.

## Quick start

Requires **Python 3.9+**. The default demo needs no additional packages, API keys, or network connection.

```bash
git clone https://github.com/Aamynn/wazuh-ai-soc-lab.git
cd wazuh-ai-soc-lab
python3 -m soc_lab --input sample-data/ssh-sequence.jsonl
```

The sample produces **one investigation with six evidence references**: five failed logins followed by a success within five minutes. Output is JSON; the default explanation is rule-based.

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

## Optional local AI

With Ollama running at `127.0.0.1:11434` and a local model already installed:

```bash
python3 -m soc_lab --input sample-data/ssh-sequence.jsonl \
  --provider ollama --model YOUR_INSTALLED_LOCAL_MODEL
```

Use a local-only Ollama configuration. Check `provider_used` and `fallback` in the output to see whether inference succeeded. Evidence-reference validation does not guarantee factual accuracy.

## Documentation

| Guide | Contents |
| --- | --- |
| [Architecture](docs/architecture.md) | Data flow, event schema, and failure handling |
| [Wazuh integration](docs/wazuh-integration.md) | Plan for connecting live telemetry |
| [Evaluation](docs/evaluation.md) | Test results and AI evaluation approach |
| [Threat model](docs/threat-model.md) | Security boundaries and limitations |
| [Project analysis](docs/project-analysis.md) | Original study and design decisions |
| [Roadmap](ROADMAP.md) | Next milestones |

For project origins and licensing status, see [NOTICE](NOTICE.md). Contribution guidance is in [CONTRIBUTING](CONTRIBUTING.md).

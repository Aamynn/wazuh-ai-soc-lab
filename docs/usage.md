# Usage

## Run from source

Python 3.9+ is sufficient for the default analysis. No runtime dependencies or model downloads are required.

```bash
python3 -m soc_lab --input sample-data/ssh-sequence.jsonl
python3 -m soc_lab --input sample-data/benign-logins.jsonl
```

The first command returns one investigation; the second returns none. Both use synthetic events.

## Install the command

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
soc-lab --version
soc-lab --help
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell. Installation may download build tooling; runtime baseline analysis is offline. After installation, `soc-lab` can run from any directory using an absolute input path. Prompts and runbooks are included in the package. No package is published to PyPI.

## Readable reports

```bash
python3 -m soc_lab --input sample-data/ssh-sequence.jsonl --format markdown
mkdir -p artifacts
python3 -m soc_lab --input sample-data/ssh-sequence.jsonl \
  --format markdown --output artifacts/investigation.md
```

Output files must be new; existing files, including the input, are never overwritten. The parent directory must exist. Reports can contain sensitive identity information when using your own data. Markdown escapes event/model content and does not generate executable actions.

See the [generated sample report](examples/ssh-investigation.md). Regenerate it with the command above; do not manually edit evidence in a generated report.

## Tune the detection

```bash
python3 -m soc_lab --input sample-data/ssh-sequence.jsonl \
  --threshold 5 --window-seconds 300
```

Threshold: 1–99 failures. Window: 1–86,400 seconds. Defaults remain five failures in five minutes before a success. Both values appear in JSON report configuration. Changing them changes the detection and may increase false positives. The bundled runbook describes the default heuristic; use recorded configuration when reviewing custom runs.

## Local AI

```bash
python3 -m soc_lab --input sample-data/ssh-sequence.jsonl \
  --provider ollama --model YOUR_INSTALLED_LOCAL_MODEL --format markdown
```

Ollama must be running on `127.0.0.1:11434`, with a suitable local model already installed. Configure the server for local-only inference. The CLI does not install models. When the provider fails or returns invalid output, the report uses the baseline and marks the fallback. Real-model evaluation is still pending.

## Exit codes and troubleshooting

| Code | Meaning |
| --- | --- |
| 0 | Report generated; inspect provider/fallback fields for AI status |
| 2 | Invalid arguments, invalid input, input limits, or file output error |

- **Invalid event on line N:** compare with the [normalized schema](architecture.md); timestamps require a timezone. Raw Wazuh JSON is not accepted.
- **Duplicate IDs/fields:** fix the export; conflicting values are not guessed.
- **No investigations:** verify the same host/account/IP, threshold, and time window. No result does not establish safety.
- **Evidence or investigation limit:** narrow the input batch. The tool fails rather than silently discarding evidence.
- **AI fallback:** confirm the local server/model and inspect `failure_type` in JSON. Invalid response bodies are not copied into errors.
- **File exists:** choose a new output filename. There is no force-overwrite option.

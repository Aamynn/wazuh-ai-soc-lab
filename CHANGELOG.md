# Changelog

## 0.2.0

- Added an installable `soc-lab` command with packaged prompts and runbooks.
- Added Markdown investigation reports and non-overwriting file output.
- Exposed detection thresholds and time windows through CLI options; reports record the configuration.
- Replaced repeated full-group correlation scans with a sliding time window, retaining exact-time and entity boundaries.
- Rejected duplicate JSON fields and non-standard constants; handled extreme timestamps and interrupted model responses.
- Escaped untrusted report text and fixed the whitespace bypass in analysis-length validation.
- Expanded regression checks, package-install CI, usage documentation, and contribution templates.

## 0.1.0

- Initial synthetic SSH investigation demo, optional local Ollama adapter, 22 functional tests, and project documentation.

# Contributing

Run `python3 -m unittest discover -s tests -v` and both documented fixture commands before proposing a change. The supported baseline is Python 3.9+ with the standard library only.

Install with `python -m pip install .` in a virtual environment and verify `soc-lab` from outside the checkout when changing packaging or resources. CI checks package installation and compares the generated Markdown report with `docs/examples/ssh-investigation.md`. If report behavior changes intentionally, regenerate that example and review its diff. See [usage](docs/usage.md) and update [the changelog](CHANGELOG.md) for user-visible changes.

For detections, include positive and benign cases, expected evidence, telemetry prerequisites, and limitations. For model/provider changes, test invalid outputs and failures without requiring live credentials in CI. Clearly distinguish deterministic output from real inference.

Use only synthetic or explicitly sanitized fixtures. Do not contribute live credentials, enrollment keys, private telemetry, or organizational screenshots. Keep citations and attribution for upstream material; no repository-wide license is selected yet.

Avoid adding autonomous endpoint actions to the analysis boundary. Changes to input limits, network destinations, or persistence need an update to the threat model.

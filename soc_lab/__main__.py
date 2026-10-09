"""CLI entry point: python3 -m soc_lab --input sample-data/ssh-sequence.jsonl."""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze, build_request
from .core import correlate, load_events
from .reporting import markdown_report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evidence-linked SSH lab investigation; baseline is not AI.")
    parser.add_argument("--input", required=True, help="normalized UTF-8 JSONL file")
    parser.add_argument("--provider", choices=("baseline", "ollama"), default="baseline")
    parser.add_argument("--model", help="installed local Ollama model, required for ollama")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--threshold", type=int, default=5, help="failures required before success (1-99; default: 5)")
    parser.add_argument("--window-seconds", type=int, default=300, help="look-back window (1-86400; default: 300)")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="save to a NEW file instead of stdout; existing files are never overwritten")
    args = parser.parse_args(argv)
    if args.provider == "ollama" and not args.model:
        parser.error("--model is required for ollama")
    if args.provider == "baseline" and args.model:
        parser.error("--model only applies to ollama")
    try:
        if args.provider == "ollama":
            build_request({}, args.model)  # Fail invalid configuration even with zero incidents.
        events, digest = load_events(args.input)
        incidents = correlate(events, args.threshold, args.window_seconds)
        investigations = [dict(incident, **analyze(incident, args.provider, args.model)) for incident in incidents]
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    report = {
        "schema_version": "1", "application_version": __version__,
        "configuration": {"threshold": args.threshold, "window_seconds": args.window_seconds},
        "input_sha256": digest, "event_count": len(events),
        "investigation_count": len(investigations), "investigations": investigations,
    }
    rendered = markdown_report(report) if args.format == "markdown" else json.dumps(report, indent=2, sort_keys=True)
    try:
        if args.output:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(rendered.rstrip() + "\n")
        else:
            print(rendered)
    except OSError as exc:
        print("error writing report: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

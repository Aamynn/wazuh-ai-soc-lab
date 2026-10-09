"""CLI entry point: python3 -m soc_lab --input sample-data/ssh-sequence.jsonl."""

import argparse
import json
import sys

from . import __version__
from .analysis import analyze, build_request
from .core import correlate, load_events


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evidence-linked SSH lab investigation; baseline is not AI.")
    parser.add_argument("--input", required=True, help="normalized UTF-8 JSONL file")
    parser.add_argument("--provider", choices=("baseline", "ollama"), default="baseline")
    parser.add_argument("--model", help="installed local Ollama model, required for ollama")
    args = parser.parse_args(argv)
    if args.provider == "ollama" and not args.model:
        parser.error("--model is required for ollama")
    if args.provider == "baseline" and args.model:
        parser.error("--model only applies to ollama")
    try:
        if args.provider == "ollama":
            build_request({}, args.model)  # Fail invalid configuration even with zero incidents.
        events, digest = load_events(args.input)
        incidents = correlate(events)
        investigations = [dict(incident, **analyze(incident, args.provider, args.model)) for incident in incidents]
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    report = {
        "schema_version": "1", "application_version": __version__,
        "input_sha256": digest, "event_count": len(events),
        "investigation_count": len(investigations), "investigations": investigations,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

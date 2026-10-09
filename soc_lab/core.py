"""Small, bounded correlation engine for normalized lab events."""

import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_BYTES = 2_000_000
MAX_EVENTS = 2_000
MAX_INCIDENTS = 20
MAX_EVIDENCE = 100
REQUIRED = {"id", "timestamp", "host", "user", "source_ip", "event_type"}
TOKEN = re.compile(r"[A-Za-z0-9_.@\\\-]{1,128}\Z")


def parse_time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("timestamp must be an ISO-8601 string")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if result.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return result.astimezone(timezone.utc)


def normalize_event(value):
    if not isinstance(value, dict) or not REQUIRED.issubset(value):
        raise ValueError("event is missing required normalized fields")
    # Unknown fields (including raw messages and secrets) never enter context.
    event = {key: value[key] for key in sorted(REQUIRED)}
    for key in ("id", "host", "user"):
        if not isinstance(event[key], str) or not TOKEN.fullmatch(event[key]):
            raise ValueError("invalid identifier: " + key)
    event["timestamp"] = parse_time(event["timestamp"]).isoformat()
    if not isinstance(event["source_ip"], str):
        raise ValueError("source_ip must be an IP address string")
    try:
        event["source_ip"] = str(ipaddress.ip_address(event["source_ip"]))
    except ValueError as exc:
        raise ValueError("invalid source_ip") from exc
    if event["event_type"] not in ("ssh_failed", "ssh_success"):
        raise ValueError("unsupported event_type")
    return event


def load_events(path):
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("input exceeds 2 MB limit")
    events, seen = [], set()
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("input must be UTF-8 JSONL") from exc
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        if len(events) >= MAX_EVENTS:
            raise ValueError("input exceeds event limit")
        try:
            event = normalize_event(json.loads(line))
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid event on line {}: {}".format(number, exc)) from exc
        if event["id"] in seen:
            raise ValueError("duplicate event id on line {}".format(number))
        seen.add(event["id"])
        events.append(event)
    return sorted(events, key=lambda event: (event["timestamp"], event["id"])), hashlib.sha256(raw).hexdigest()


def correlate(events, threshold=5, window_seconds=300):
    """One investigation per qualifying success; ties are not considered prior."""
    if type(threshold) is not int or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    if type(window_seconds) is not int or window_seconds < 1:
        raise ValueError("window_seconds must be a positive integer")
    validated, seen = [], set()
    for raw in events:
        event = normalize_event(raw)
        if event["id"] in seen:
            raise ValueError("duplicate event id")
        seen.add(event["id"])
        validated.append(event)
        if len(validated) > MAX_EVENTS:
            raise ValueError("input exceeds event limit")
    groups = defaultdict(list)
    for event in validated:
        groups[(event["host"], event["user"], event["source_ip"])].append(event)
    incidents = []
    for key, group in sorted(groups.items()):
        group.sort(key=lambda event: (parse_time(event["timestamp"]), event["id"]))
        for success in (event for event in group if event["event_type"] == "ssh_success"):
            end = parse_time(success["timestamp"])
            start = end - timedelta(seconds=window_seconds)
            failures = [event for event in group if event["event_type"] == "ssh_failed"
                        and start <= parse_time(event["timestamp"]) < end]
            if len(failures) < threshold:
                continue
            if len(failures) + 1 > MAX_EVIDENCE:
                raise ValueError("incident exceeds evidence limit; narrow the input window")
            incidents.append({
                "incident_id": "ssh-" + success["id"],
                "rule_id": "LAB-SSH-001",
                "host": key[0], "user": key[1], "source_ip": key[2],
                "failure_count": len(failures), "window_seconds": window_seconds,
                "events": failures + [success],
            })
            if len(incidents) > MAX_INCIDENTS:
                raise ValueError("too many investigations; narrow the input window")
    return sorted(incidents, key=lambda incident: (incident["events"][-1]["timestamp"], incident["incident_id"]))

"""Small, bounded correlation engine for normalized lab events."""

import hashlib
import ipaddress
import json
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from itertools import groupby

MAX_BYTES = 2_000_000
MAX_EVENTS = 2_000
MAX_INCIDENTS = 20
MAX_EVIDENCE = 100
REQUIRED = {"id", "timestamp", "host", "user", "source_ip", "event_type"}
TOKEN = re.compile(r"[A-Za-z0-9_.@\\\-]{1,128}\Z")


def strict_json(text):
    """Reject ambiguous duplicate keys and non-JSON numeric constants."""
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("non-standard JSON constant")

    return json.loads(text, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)


def parse_time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("timestamp must be an ISO-8601 string")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if result.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    try:
        return result.astimezone(timezone.utc)
    except OverflowError as exc:
        raise ValueError("timestamp is outside supported UTC range") from exc


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
            event = normalize_event(strict_json(line))
        except (ValueError, TypeError, RecursionError) as exc:
            raise ValueError("invalid event on line {}".format(number)) from exc
        if event["id"] in seen:
            raise ValueError("duplicate event id on line {}".format(number))
        seen.add(event["id"])
        events.append(event)
    return sorted(events, key=lambda event: (parse_time(event["timestamp"]), event["id"])), hashlib.sha256(raw).hexdigest()


def correlate(events, threshold=5, window_seconds=300):
    """One investigation per qualifying success; ties are not considered prior."""
    if type(threshold) is not int or not 1 <= threshold < MAX_EVIDENCE:
        raise ValueError("threshold must be between 1 and 99")
    if type(window_seconds) is not int or not 1 <= window_seconds <= 86400:
        raise ValueError("window_seconds must be between 1 and 86400")
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
        timed = sorted((parse_time(event["timestamp"]), event["id"], event) for event in group)
        failures = deque()
        for instant, batch in groupby(timed, key=lambda item: item[0]):
            batch = list(batch)
            try:
                start = instant - timedelta(seconds=window_seconds)
            except OverflowError:
                start = datetime.min.replace(tzinfo=timezone.utc)
            while failures and failures[0][0] < start:
                failures.popleft()
            # Process successes before adding equal-time failures: order is unknown.
            for _, _, success in batch:
                if success["event_type"] != "ssh_success" or len(failures) < threshold:
                    continue
                if len(failures) + 1 > MAX_EVIDENCE:
                    raise ValueError("incident exceeds evidence limit; narrow the input window")
                incidents.append({
                    "incident_id": "ssh-" + success["id"],
                    "rule_id": "LAB-SSH-001",
                    "host": key[0], "user": key[1], "source_ip": key[2],
                    "failure_count": len(failures), "window_seconds": window_seconds,
                    "threshold": threshold,
                    "events": [event for _, event in failures] + [success],
                })
                if len(incidents) > MAX_INCIDENTS:
                    raise ValueError("too many investigations; narrow the input window")
            failures.extend((instant, event) for _, _, event in batch if event["event_type"] == "ssh_failed")
    return sorted(incidents, key=lambda incident: (parse_time(incident["events"][-1]["timestamp"]), incident["incident_id"]))

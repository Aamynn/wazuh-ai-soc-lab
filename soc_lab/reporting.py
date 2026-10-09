"""Readable reports; all event and model text is escaped for Markdown."""

import html
import re


def escape(value):
    text = html.escape(str(value), quote=True)
    text = "".join(char for char in text if ord(char) >= 32 or char == "\n")
    text = re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text)
    return text.replace("\n", " ")


def markdown_report(report):
    lines = ["# SOC investigation report", "",
             "Events: **{}** · Investigations: **{}**".format(report["event_count"], report["investigation_count"]),
             "", "Input SHA-256: `{}`".format(report["input_sha256"]), ""]
    if not report["investigations"]:
        lines += ["No sequences matched the configured rule. This does not establish that the activity is safe.", ""]
    for item in report["investigations"]:
        analysis, provenance = item["analysis"], item["provenance"]
        lines += ["## " + escape(item["incident_id"]), "",
                  "**Host:** {} · **Account:** {} · **Source:** {}".format(escape(item["host"]), escape(item["user"]), escape(item["source_ip"])),
                  "", "**Assessment:** {} · **Human review required**".format(escape(analysis["assessment"])),
                  "", escape(analysis["summary"]), "",
                  "**Analysis provider:** {} · **Fallback:** {}".format(escape(provenance["provider_used"]), str(provenance["fallback"]).lower()),
                  "", "### Evidence timeline", "",
                  "| Time (UTC) | Event | Evidence ID |", "| --- | --- | --- |"]
        for event in item["events"]:
            lines.append("| {} | {} | {} |".format(escape(event["timestamp"]), escape(event["event_type"]), escape(event["id"])))
        lines += ["", "**Cited evidence:** " + ", ".join(escape(value) for value in analysis["evidence_ids"]),
                  "", "**Runbook:** " + ", ".join(escape(value) for value in analysis["runbook_ids"])]
        for title, key in (("Missing context", "missing_context"), ("Recommended checks", "recommended_checks")):
            lines += ["", "### " + title, ""]
            lines.extend("- " + escape(value) for value in analysis[key])
        lines += ["", "AI suggestions are not verified findings. Consult the JSON report for full provenance.", ""]
    return "\n".join(lines)

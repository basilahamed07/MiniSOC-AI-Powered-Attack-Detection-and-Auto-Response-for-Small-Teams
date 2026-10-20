"""Deterministic JSON and Markdown reports for synthetic MiniSOC snapshots."""

from __future__ import annotations

import json
import html
import re
from pathlib import Path

from .workflow import Snapshot


def _markdown_value(value: object) -> str:
    return f"<code>{html.escape(str(value), quote=True)}</code>"


def _markdown_block(value: object) -> list[str]:
    """Render arbitrary evidence in a fence longer than any input backtick run."""

    text = str(value)
    longest_run = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest_run + 1)
    return [fence, text, fence]


def export_json(snapshot: Snapshot, path: str | Path) -> Path:
    output = Path(path)
    output.write_text(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def export_markdown(snapshot: Snapshot, path: str | Path) -> Path:
    output = Path(path)
    data = snapshot.to_dict()
    summary = data["summary"]
    lines = [
        "# MiniSOC Synthetic Incident Report",
        "",
        f"- Scenario: `{snapshot.scenario}`",
        f"- Seed: `{snapshot.seed}`",
        "- Safety: generated sample data only; no live collection or real scanning",
        "",
        "## Summary",
        "",
        f"- Events: **{summary['event_count']}**",
        f"- Alerts: **{summary['alert_count']}**",
        f"- Incidents: **{summary['incident_count']}**",
        f"- High severity alerts: **{summary['high_alert_count']}**",
        "",
        "## Alerts",
        "",
        "| Ref | Severity | Detection | Source IP | Risk | ATT&CK | Incident | Evidence |",
        "|---|---|---|---|---:|---|---|---:|",
    ]
    for alert in data["alerts"]:
        lines.append(
            f"| {alert['reference']} | {alert['severity']} | {alert['attack_type']} | "
            f"`{alert['ip']}` | {alert['risk_score']} | {alert['mitre_id']} | "
            f"{alert['incident_id']} | {len(alert['evidence'])} |"
        )
    if not data["alerts"]:
        lines.append("| — | — | No detections | — | — | — | — | 0 |")
    lines.extend(["", "## Incident timelines", ""])
    for incident in data["incidents"]:
        lines.extend(
            [
                f"### `{incident['incident_id']}` · `{incident['ip']}`",
                "",
                f"- Risk score: **{incident['risk_score']}**",
                f"- Attack types: {', '.join(incident['attack_types'])}",
                f"- Alerts: {', '.join(incident['alert_references'])}",
                "",
            ]
        )
        for alert in data["alerts"]:
            if alert["reference"] not in incident["alert_references"]:
                continue
            lines.append(
                f"#### `{alert['reference']}` · {alert['attack_type']} · {alert['timestamp']}"
            )
            lines.append("")
            lines.append(f"Rule evidence: `{len(alert['evidence'])}` event(s); ATT&CK `{alert['mitre_id']}`.")
            lines.append("")
            for evidence in alert["evidence"]:
                lines.extend(
                    [
                        f"- Event {_markdown_value(evidence.get('event_id', 'unknown'))} at "
                        f"{_markdown_value(evidence.get('timestamp', 'unknown'))}",
                        "  - Raw:",
                    ]
                )
                lines.extend(_markdown_block(evidence.get("raw", "")))
                for key in ("port", "target", "username", "matched_rule", "decoded_target"):
                    if key in evidence:
                        lines.append(f"  - {key}: {_markdown_value(evidence[key])}")
            lines.append("")
    if not data["incidents"]:
        lines.append("No incidents were created by this synthetic scenario.")
    lines.extend(["", "## Simulated responses", ""])
    for response in data["responses"]:
        lines.append(f"- `{response['action']}` for `{response['ip']}` — **{response['status']}** ({response['reason']})")
    if not data["responses"]:
        lines.append("- No simulated block decisions in this sample.")
    lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")
    return output

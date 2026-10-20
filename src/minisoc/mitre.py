"""Static MITRE ATT&CK mappings for the explainable prototype rules."""

from __future__ import annotations

MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "brute_force": {"id": "T1110", "name": "Brute Force"},
    "port_scan": {"id": "T1046", "name": "Network Service Scanning"},
    "sql_injection": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
    },
    "path_traversal": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
    },
}


def technique_for(attack_type: str) -> dict[str, str]:
    """Return a copy of the mapping so callers cannot mutate global policy."""

    try:
        return dict(MITRE_TECHNIQUES[attack_type])
    except KeyError as exc:
        raise ValueError(f"unsupported attack type: {attack_type}") from exc

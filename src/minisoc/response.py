"""Safe response simulation; this module never changes host firewall state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .incidents import EnrichedAlert


@dataclass(frozen=True, slots=True)
class ResponseAction:
    action_id: str
    ip: str
    action: str
    status: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "action_id": self.action_id,
            "ip": self.ip,
            "action": self.action,
            "status": self.status,
            "reason": self.reason,
        }


def simulate_auto_block(
    alerts: Iterable[EnrichedAlert], threshold: int = 65
) -> list[ResponseAction]:
    """Return simulated block decisions without sockets, subprocesses, or OS calls."""

    if not 0 <= threshold <= 100:
        raise ValueError("threshold must be between 0 and 100")
    selected: dict[str, EnrichedAlert] = {}
    for alert in alerts:
        if alert.risk_score >= threshold:
            selected.setdefault(alert.alert.ip, alert)
    return [
        ResponseAction(
            action_id=f"response-{index:03d}",
            ip=ip,
            action="block_ip",
            status="simulated",
            reason=f"risk_score >= {threshold} ({selected[ip].risk_score})",
        )
        for index, ip in enumerate(sorted(selected), start=1)
    ]

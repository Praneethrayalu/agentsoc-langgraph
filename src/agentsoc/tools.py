"""Read-only tools. No shell, network scanning, blocking, or arbitrary file reads."""

import ipaddress
import json
from pathlib import Path


class EvidenceTools:
    def __init__(self, directory: Path):
        self.reputation = json.loads((directory / "reputation.json").read_text())
        self.logs = [json.loads(line) for line in (directory / "logs.jsonl").read_text().splitlines() if line]

    def ip_reputation(self, address: str | None) -> dict:
        if not address:
            return {"status": "unknown", "source": "no IP supplied"}
        ipaddress.ip_address(address)
        record = self.reputation.get(address)
        return record or {"status": "unknown", "source": "not in offline snapshot"}

    def log_search(self, host: str, alert_id: str, limit: int = 30) -> list[dict]:
        # Exact joins prevent cross-host evidence leakage. Output is bounded.
        return [row for row in self.logs if row.get("host") == host and row.get("alert_id") == alert_id][
            : min(max(limit, 0), 30)
        ]

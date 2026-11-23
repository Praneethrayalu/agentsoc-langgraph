"""Synthetic lab dataset, never claimed to be real incident traffic.

100 manually specified scenario variants. This is a smoke benchmark, not a
statistical estimate of production detection performance. Labels correspond to
an explicit evidence policy. Same scenario families recur across variants.
"""

import json
from pathlib import Path

SCENARIOS = [
    (
        "Encoded PowerShell process",
        "An endpoint launched an encoded PowerShell command.",
        "execution",
        "encoded_command",
        "review",
    ),
    (
        "Credential access alert",
        "A process accessed LSASS memory and wrote a dump.",
        "execution",
        "credential_dump",
        "malicious",
    ),
    (
        "Large outbound transfer",
        "A scheduled backup transferred data to an external server.",
        "network",
        "approved_change",
        "benign",
    ),
    (
        "Large outbound transfer",
        "An external transfer exceeded the normal volume.",
        "network",
        "exfiltration",
        "malicious",
    ),
    (
        "Failed authentication burst",
        "Repeated failed logins for a user account.",
        "authentication",
        "failed_logins",
        "review",
    ),
    (
        "New binary execution",
        "A new signed package was installed in a maintenance window.",
        "execution",
        "approved_change",
        "benign",
    ),
    (
        "Network beacon pattern",
        "Periodic connections from an endpoint to an external service.",
        "network",
        "c2_beacon",
        "malicious",
    ),
    (
        "Antivirus detection",
        "Endpoint telemetry indicates file encryption activity.",
        "file",
        "ransomware",
        "malicious",
    ),
    (
        "Unusual remote login",
        "Remote sign-in from a new address, context not available.",
        "authentication",
        None,
        "review",
    ),
    (
        "Command shell activity",
        "A scheduled maintenance script ran on the endpoint.",
        "execution",
        "approved_change",
        "benign",
    ),
]


def main():
    alerts, logs, reputation = [], [], {}
    for variant in range(10):
        for scenario, (title, desc, category, signal, label) in enumerate(SCENARIOS):
            ident = f"lab-{variant:02d}-{scenario:02d}"
            host = f"endpoint-{variant + 1:02d}"
            ip = f"192.0.2.{variant * 10 + scenario + 1}"
            alert = {
                "id": ident,
                "host": host,
                "title": title,
                "description": desc
                + f" Process context: user{variant + 1}, event series {variant * 37 + scenario}.",
                "source_ip": ip,
                "category": category,
            }
            alerts.append({"alert": alert, "label": label, "family": scenario})
            if signal:
                logs.append(
                    {
                        "host": host,
                        "alert_id": ident,
                        "signal": signal,
                        "source": "synthetic_endpoint",
                        "event_id": variant * 100 + scenario,
                    }
                )
            if scenario == 6:
                reputation[ip] = {"status": "malicious", "source": "synthetic lab reputation snapshot"}
    Path("data/alerts.jsonl").write_text("\n".join(json.dumps(a) for a in alerts) + "\n")
    Path("data/logs.jsonl").write_text("\n".join(json.dumps(a) for a in logs) + "\n")
    Path("data/reputation.json").write_text(json.dumps(reputation, indent=2))
    print("Wrote 100 synthetic alerts across 10 families. All IPs are RFC 5737 documentation addresses.")


if __name__ == "__main__":
    main()

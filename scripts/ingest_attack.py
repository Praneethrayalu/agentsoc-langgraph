"""Fetch and pin the official ATT&CK STIX corpus. No executable remote content."""

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

from agentsoc.retrieval import AttackIndex

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--index", default=".cache/chroma")
    args = parser.parse_args()
    raw = args.source.read_bytes() if args.source else urllib.request.urlopen(URL, timeout=120).read()
    source = json.loads(raw)
    docs = []
    for obj in source["objects"]:
        if obj["type"] != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None
        )
        if ref and "external_id" in ref:
            docs.append(
                {
                    "id": ref["external_id"],
                    "name": obj["name"],
                    "text": obj.get("description", ""),
                    "url": ref["url"],
                }
            )
    Path("data/attack_techniques.json").write_text(json.dumps(docs, indent=2))
    Path("data/attack_manifest.json").write_text(
        json.dumps(
            {
                "source_url": URL,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bundle_id": source["id"],
                "technique_count": len(docs),
                "latest_object_modified": max(o.get("modified", "") for o in source["objects"]),
                "embedding": "sklearn HashingVectorizer 2048 dimensions, word 1-2gram; not neural",
            },
            indent=2,
        )
    )
    AttackIndex(args.index).load(docs)
    print(f"Indexed {len(docs)} active Enterprise ATT&CK techniques and sub-techniques")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Independently verify the audit log's hash chain has not been tampered with.

Deliberately has zero dependency on Claude/the skill's own writer — an auditor
(or their tooling) should be able to run this cold against the raw JSONL file.
"""
import hashlib
import json
import os
import sys

LOG_PATH = os.path.expanduser("~/.soc_audit/audit_log.jsonl")


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def main():
    if not os.path.exists(LOG_PATH):
        print("No audit log found at", LOG_PATH)
        return

    expected_prev = "0" * 64
    with open(LOG_PATH) as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            stored_hash = entry.pop("entry_hash")
            if entry["prev_hash"] != expected_prev:
                sys.exit(f"BROKEN CHAIN at line {i}: prev_hash mismatch "
                          f"(expected {expected_prev[:12]}..., got {entry['prev_hash'][:12]}...)")
            recomputed = hashlib.sha256((entry["prev_hash"] + canonical_json(entry)).encode()).hexdigest()
            if recomputed != stored_hash:
                sys.exit(f"TAMPERED ENTRY at line {i} (alert_id={entry.get('alert_id')}): "
                         f"stored hash does not match recomputed hash. Entry was edited after logging.")
            expected_prev = stored_hash

    print(f"OK: {i} entries verified, chain intact, no tampering detected.")


if __name__ == "__main__":
    main()

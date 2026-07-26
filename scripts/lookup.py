#!/usr/bin/env python3
"""Print every audit log entry for a given alert_id (handles reopen/reclose history)."""
import json
import os
import sys

LOG_PATH = os.path.expanduser("~/.soc_audit/audit_log.jsonl")


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: lookup.py <alert_id>")
    alert_id = sys.argv[1]
    if not os.path.exists(LOG_PATH):
        print("No audit log found.")
        return
    found = []
    with open(LOG_PATH) as f:
        for line in f:
            entry = json.loads(line)
            if entry["alert_id"] == alert_id:
                found.append(entry)
    if not found:
        print(f"No entries for alert_id={alert_id}")
        return
    for e in found:
        print(json.dumps(e, indent=2))
    if len(found) > 1:
        print(f"\nNOTE: {len(found)} entries found for this alert_id — it was reopened/reclosed. "
              "This is expected and preserved; the log never edits history.")


if __name__ == "__main__":
    main()

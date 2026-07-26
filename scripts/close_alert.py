#!/usr/bin/env python3
"""Append a hash-chained, auditor-reproducible alert-closure entry.

Never writes partial entries and never edits history — the log is append-only.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

LOG_DIR = os.path.expanduser("~/.soc_audit")
LOG_PATH = os.path.join(LOG_DIR, "audit_log.jsonl")
CONTROL_MAP_PATH = os.path.join(os.path.dirname(__file__), "control_map.json")

VALID_REASONS = [
    "true_positive_escalated",
    "false_positive_confirmed",
    "benign_expected_behavior",
    "duplicate_of_existing_incident",
    "insufficient_evidence_closed_monitoring",
]

VALID_SEVERITIES = ["informational", "low", "medium", "high", "critical"]


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def last_hash():
    if not os.path.exists(LOG_PATH):
        return "0" * 64
    last_line = None
    with open(LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                last_line = line
    if last_line is None:
        return "0" * 64
    return json.loads(last_line)["entry_hash"]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--alert-id", required=True, help="Splunk notable event ID")
    p.add_argument("--rule-name", required=True, help="Correlation search / alert rule name")
    p.add_argument("--severity", required=True, choices=VALID_SEVERITIES)
    p.add_argument("--closure-reason", required=True, choices=VALID_REASONS)
    p.add_argument("--spl-query", required=True,
                    help="Exact SPL that reproduces the alert evidence, e.g. "
                         "'index=firewall sourcetype=cisco:asa earliest=-24h ...'")
    p.add_argument("--reasoning", required=True,
                    help="Actual analytical reasoning, evidence reviewed, and what ruled out "
                         "alternative verdicts. Not a one-line summary.")
    p.add_argument("--mitre-technique", default=None, help="e.g. T1110 (optional but recommended)")
    p.add_argument("--analyst", required=True,
                    help="Who is accountable for this closure: analyst email, or "
                         "'llm-autonomous:<model-id>' if no human reviewed it")
    p.add_argument("--human-reviewed", action="store_true",
                    help="Set if a human analyst reviewed/approved the LLM's verdict before closure")

    args = p.parse_args()

    if len(args.reasoning.strip()) < 30:
        sys.exit("ERROR: --reasoning is too short to be auditor-reproducible. "
                  "Explain the evidence reviewed and what ruled out alternatives.")
    if "index=" not in args.spl_query and "search" not in args.spl_query.lower():
        sys.exit("ERROR: --spl-query doesn't look like a real SPL search. "
                  "This field must let an auditor reproduce the alert independently.")

    os.makedirs(LOG_DIR, exist_ok=True)
    with open(CONTROL_MAP_PATH) as f:
        control_map = json.load(f)[args.closure_reason]

    prev_hash = last_hash()
    timestamp = datetime.now(timezone.utc).isoformat()

    entry = {
        "timestamp_utc": timestamp,
        "alert_id": args.alert_id,
        "rule_name": args.rule_name,
        "severity": args.severity,
        "closure_reason": args.closure_reason,
        "spl_query": args.spl_query,
        "reasoning": args.reasoning,
        "mitre_technique": args.mitre_technique,
        "analyst": args.analyst,
        "human_reviewed": bool(args.human_reviewed),
        "control_ref": control_map,
        "prev_hash": prev_hash,
    }
    entry_hash = hashlib.sha256((prev_hash + canonical_json(entry)).encode()).hexdigest()
    entry["entry_hash"] = entry_hash

    with open(LOG_PATH, "a") as f:
        f.write(canonical_json(entry) + "\n")

    line_no = sum(1 for _ in open(LOG_PATH))
    print(f"Logged. alert_id={args.alert_id} log_line={line_no} entry_hash={entry_hash[:12]}...")


if __name__ == "__main__":
    main()

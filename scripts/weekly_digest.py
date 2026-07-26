#!/usr/bin/env python3
"""Flag closure-reason drift per alert rule: trailing 7 days vs trailing 90-day baseline.

Rubber-stamping signature: a rule's false_positive/benign closure rate spikes while
its true_positive rate doesn't move — usually means the LLM (or an analyst) stopped
actually evaluating a noisy rule and started auto-dismissing it.
"""
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone

LOG_PATH = os.path.expanduser("~/.soc_audit/audit_log.jsonl")
DRIFT_THRESHOLD_POINTS = 15


def load_entries():
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH) as f:
        return [json.loads(l) for l in f if l.strip()]


def rate_table(entries):
    by_rule = defaultdict(lambda: defaultdict(int))
    for e in entries:
        by_rule[e["rule_name"]][e["closure_reason"]] += 1
    rates = {}
    for rule, counts in by_rule.items():
        total = sum(counts.values())
        rates[rule] = {
            reason: (100.0 * n / total) for reason, n in counts.items()
        } if total else {}
        rates[rule]["_total"] = total
    return rates


def main():
    entries = load_entries()
    if not entries:
        print("No audit log entries yet.")
        return

    now = datetime.fromisoformat(entries[-1]["timestamp_utc"])
    week_ago = now - timedelta(days=7)
    baseline_start = now - timedelta(days=90)

    def in_window(e, start, end):
        ts = datetime.fromisoformat(e["timestamp_utc"])
        return start <= ts <= end

    recent = [e for e in entries if in_window(e, week_ago, now)]
    baseline = [e for e in entries if in_window(e, baseline_start, week_ago)]

    if not recent:
        print("No closures in the trailing 7 days.")
        return

    recent_rates = rate_table(recent)
    baseline_rates = rate_table(baseline) if baseline else {}

    print(f"Weekly digest: {len(recent)} closures (trailing 7d) vs {len(baseline)} (prior 83d baseline)\n")

    flagged = False
    for rule, r_rates in recent_rates.items():
        b_rates = baseline_rates.get(rule, {})
        for reason in ("false_positive_confirmed", "benign_expected_behavior"):
            r = r_rates.get(reason, 0.0)
            b = b_rates.get(reason, 0.0)
            if b_rates and (r - b) >= DRIFT_THRESHOLD_POINTS:
                flagged = True
                print(f"⚠ DRIFT: rule='{rule}' reason='{reason}' "
                      f"{b:.0f}% (baseline) -> {r:.0f}% (this week) "
                      f"(+{r-b:.0f} pts, n={r_rates['_total']} this week)")
                print("   Possible rubber-stamping — spot-check recent closures for this rule.\n")

    if not flagged:
        print("No closure-reason drift above threshold. No rubber-stamping signature detected.")


if __name__ == "__main__":
    main()

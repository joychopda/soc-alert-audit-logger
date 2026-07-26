# SOC Alert Audit-Trail Logger

A Claude Skill that intercepts LLM alert-closure decisions during Splunk notable-event
triage and logs them in a tamper-evident, auditor-reproducible format — built to satisfy
SOC 2 (CC7.2/CC7.3) and ISO 27001 (A.5.24/A.5.25) evidence requirements for LLM-assisted
SOC triage.

## Why

Most "AI audit logging" is `{"alert": "X", "verdict": "FP"}` in a text file. That fails an
actual audit, because it can't answer:

1. Who/what closed the alert, and why — in a fixed, defensible taxonomy, not free text.
2. Can I re-run the exact search that produced this alert and get the same evidence?
3. Has this log entry been edited since it was written?
4. What was the actual reasoning, not just the verdict?

This skill forces every closure through a script that answers all four, and adds a
weekly digest that catches LLM (or analyst) rubber-stamping before it becomes a missed
incident.

## Install

Drop this folder into `~/.claude/skills/soc-alert-audit-logger/` (or your project's
`.claude/skills/`). Claude will pick up `SKILL.md` automatically.

## How it works

- **`scripts/close_alert.py`** — the only way an entry gets written. Requires the
  reproducing SPL query, a closure reason from a fixed taxonomy, and real analytical
  reasoning (min length enforced). Appends to `~/.soc_audit/audit_log.jsonl`, chaining
  each entry to the previous one via SHA-256 so the log is tamper-evident.
- **`scripts/verify_chain.py`** — independent, zero-Claude-dependency verifier. Point an
  auditor's own tooling at this and the raw JSONL file.
- **`scripts/lookup.py <alert_id>`** — full closure history for one alert (handles
  reopened/reclosed alerts).
- **`scripts/weekly_digest.py`** — flags when a rule's false-positive/benign closure rate
  jumps >15 points vs. its 90-day baseline — the signature of rubber-stamping a noisy rule.
- **`scripts/control_map.json`** — maps each closure reason to SOC2/ISO27001 controls.
  Edit this to match what your specific auditor asks for.

## Closure taxonomy

- `true_positive_escalated`
- `false_positive_confirmed`
- `benign_expected_behavior`
- `duplicate_of_existing_incident`
- `insufficient_evidence_closed_monitoring`

## Status

Actively maintained. The SPL-reproduction requirement currently expects the query to be
supplied in-session; a live Splunk REST API pull is a planned next step, along with
ticketing system cross-links (ServiceNow/Jira).

## License

MIT

# Skill Card: SOC Alert Audit-Trail Logger

## Description
Intercepts LLM/agent alert-closure decisions during Splunk notable-event triage and
writes them to a hash-chained, tamper-evident, auditor-reproducible log — so every
close/dismiss/escalate decision an LLM makes leaves evidence a human auditor can
independently verify without re-trusting the LLM.

## Owner
Joy Chopda ([@joychopda](https://github.com/joychopda)) — joy_chopda@lineaje.com

## License / Terms of Use
MIT. Free to use, fork, and redistribute with attribution. No warranty — this is a
logging control, not a certified compliance product; validate the control mapping
against your own auditor before relying on it for a formal SOC 2/ISO 27001 assessment.

## Use Case
For SOC teams running (or piloting) LLM-assisted alert triage against Splunk, who need
to produce defensible evidence that every LLM closure decision was evaluated, not
rubber-stamped — specifically to satisfy SOC 2 (CC7.2/CC7.3) and ISO 27001
(A.5.24/A.5.25) audit sampling. Intended users: SOC analysts, SOC leads, and
compliance/audit teams reviewing LLM-assisted triage. Not intended as a replacement for
a SIEM's own case management — it's a logging layer on top of the closure decision.

## Deployment Geography
No geographic restriction. All data (the audit log) is written locally to
`~/.soc_audit/audit_log.jsonl` on the machine running the skill — nothing is sent to a
third party or hosted service by this skill itself.

## Requirements / Dependencies
- Python 3 with only the standard library (`hashlib`, `json`, `os`, `argparse`,
  `datetime`) — no `pip install` required.
- Claude Code (or another harness that supports the Claude Skill / `SKILL.md` format).
- Splunk access sufficient to obtain the exact SPL query that produced a given notable
  event (the analyst/LLM must supply this per closure — no live Splunk API credential
  is required by the skill itself in its current version).
- Credential requirement: **No** — the skill does not itself require API keys, OAuth,
  or service accounts. (A planned future version that pulls SPL directly from Splunk's
  REST API would require a Splunk credential; not present in this version.)

## Known Risks and Mitigations
| Risk | Mitigation |
|---|---|
| LLM fabricates a plausible-looking SPL query or reasoning instead of using real evidence | `close_alert.py` requires the SPL string and a minimum-length reasoning field, but cannot itself verify the SPL was actually run — human spot-checks via `verify_chain.py`/`lookup.py` and periodic re-running of logged SPL queries are still required. |
| Log tampering / retroactive edits to closure history | Every entry is SHA-256 hash-chained to the previous entry; `verify_chain.py` runs independently of Claude and reports the first broken link. |
| Silent LLM rubber-stamping of a noisy alert rule over time | `weekly_digest.py` flags any rule whose false-positive/benign closure rate rises >15 points against its 90-day baseline. |
| Sensitive data (usernames, IPs, internal hostnames) persisted in a local plaintext log | Log is local-only by design; no network egress. Treat `~/.soc_audit/audit_log.jsonl` like any other sensitive SOC artifact (file permissions, backup policy) — the skill does not encrypt it at rest. |
| Closure taxonomy or control mapping doesn't match your actual audit framework | `scripts/control_map.json` is a single editable file — review and adjust the SOC2/ISO27001 mapping with your auditor before relying on it. |

## References
- Repository: https://github.com/joychopda/soc-alert-audit-logger
- Control mapping source file: `scripts/control_map.json`
- No external model card applicable — this skill does not itself run inference; it
  governs the logging of decisions made by whichever LLM the analyst is using in-session.

## Skill Output
- **Format:** newline-delimited JSON (JSONL), one object per closure decision, appended
  to `~/.soc_audit/audit_log.jsonl`.
- **Fields per entry:** `timestamp_utc`, `alert_id`, `rule_name`, `severity`,
  `closure_reason` (fixed taxonomy), `spl_query`, `reasoning`, `mitre_technique`
  (optional), `analyst`, `human_reviewed` (bool), `control_ref` (SOC2/ISO27001 mapping),
  `prev_hash`, `entry_hash`.
- **Constraints:** append-only — the skill provides no edit/delete path; corrections
  must be logged as new entries. `weekly_digest.py` and `verify_chain.py` output
  plain text to stdout.

## Skill Version
`v1.0.0` — see repository commit history for the release tag corresponding to this
version: https://github.com/joychopda/soc-alert-audit-logger/commits/main

## Ethical Considerations
This skill is a logging/evidence control, not a decision-maker — it does not itself
decide whether an alert is a true or false positive, and it should not be used to
create a false impression of human oversight where none occurred (`human_reviewed`
must be set honestly). Organizations should have a policy on what fraction of
LLM-autonomous closures require human review, particularly for `high`/`critical`
severity alerts; this skill logs the `human_reviewed` flag but does not enforce a
review policy itself. Misuse to fabricate audit evidence (logging a closure that
was not actually evaluated against real data) defeats the purpose of the tool and
should be treated as a control failure if discovered.

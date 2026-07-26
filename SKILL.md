---
name: soc-alert-audit-logger
description: Use whenever an LLM/agent session is about to close, dismiss, suppress, or mark resolved a Splunk notable event / alert (e.g. "close this alert as false positive", "mark this notable resolved", "dismiss as benign", "true positive - escalate"). Also use for "soc-audit weekly-digest", "soc-audit verify-log", "soc-audit lookup <alert_id>". Do NOT use for general Splunk querying that isn't a closure decision.
---

# SOC Alert Audit-Trail Logger

You are acting as the closure-decision layer for a SOC analyst who is using an LLM to triage
Splunk notable events. Every closure decision (true positive, false positive, benign,
duplicate, escalate) MUST go through this skill before you tell the user "closed" — never
just narrate a closure in chat text. An unlogged closure is a control failure (maps to
SOC 2 CC7.2/CC7.3, ISO 27001 A.5.24/A.5.25 — "documented evaluation of security events").

## Why this exists (read before skipping steps)

An auditor sampling closed alerts six months from now needs to be able to:
1. See WHO/WHAT closed the alert and WHY, in a fixed taxonomy — not free text.
2. Re-run the exact Splunk search that produced the alert and get the same evidence.
3. Verify no entry in the log was edited after the fact.
4. See the LLM's actual reasoning chain, not just the verdict.

A closure log that's just `{"alert": "X", "verdict": "FP"}` fails all four. Don't produce that.

## Required workflow for every closure decision

1. **Never close from narration alone.** If you're about to tell the user an alert is
   resolved/closed/dismissed, stop and run `scripts/close_alert.py` first. The closure only
   "counts" once it's in the log.

2. **Capture the reproducing search.** Ask for (or extract from context) the exact SPL that
   produced the notable — `index=... sourcetype=... earliest=... latest=...` — not a
   paraphrase. If you don't have it, ask the user for it before logging. This is what lets
   an auditor independently reproduce the alert months later.

3. **Force closure_reason into the fixed taxonomy** (do not invent new categories):
   - `true_positive_escalated`
   - `false_positive_confirmed`
   - `benign_expected_behavior`
   - `duplicate_of_existing_incident`
   - `insufficient_evidence_closed_monitoring`

4. **Write the actual reasoning**, not a summary. Include: what evidence you looked at,
   what ruled out the alternative verdicts, and any MITRE ATT&CK technique ID if the alert
   maps to one. This goes verbatim into the `reasoning` field.

5. **Run the script** — see `scripts/close_alert.py --help`. It:
   - appends one JSON line to `~/.soc_audit/audit_log.jsonl`
   - computes `entry_hash = sha256(prev_hash + canonical_json(entry))`, chaining every
     entry to the one before it (tamper-evident — any edit to history breaks the chain)
   - stamps `control_ref` automatically from the closure_reason (SOC2/ISO27001 mapping in
     `scripts/control_map.json`)
   - refuses to run if required fields (spl_query, reasoning, closure_reason, alert_id,
     severity) are missing — no partial/lazy entries

6. **Tell the user the alert_id and log line number**, not just "done" — they may need it
   for a ticket reference.

## Other commands

- **`soc-audit verify-log`** → run `scripts/verify_chain.py`. Walks the whole hash chain
  independently of Claude and reports the first broken link, if any. Run this if the user
  asks "has this log been tampered with" or before handing the log to an actual auditor.

- **`soc-audit lookup <alert_id>`** → run `scripts/lookup.py <alert_id>` to pull every log
  entry for a given alert (handles re-opened/re-closed alerts, which auditors always ask about).

- **`soc-audit weekly-digest`** → run `scripts/weekly_digest.py`. Computes closure-reason
  distribution for the trailing 7 days vs. the trailing 90-day baseline, per alert rule name.
  Flag it to the user in plain language if any rule's `false_positive_confirmed` or
  `benign_expected_behavior` rate jumped >15 points vs baseline — that's the signature of
  the LLM (or an analyst) starting to rubber-stamp a noisy rule instead of actually
  evaluating it, and it's the thing that turns into a missed incident.

## Non-negotiables

- Never write to `audit_log.jsonl` directly — always go through `close_alert.py` so the
  hash chain and schema validation stay intact.
- Never backdate or edit a past entry. If a closure was wrong, log a NEW entry
  (`closure_reason` can note it supersedes `alert_id`'s prior entry) — the chain is
  append-only by design, matching how auditors expect evidence logs to behave.
- If the user asks you to close an alert but hasn't given you enough to fill the schema,
  ask for the missing fields. Do not fabricate an SPL query or reasoning to make the
  script happy.

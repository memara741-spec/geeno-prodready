# Severity, confidence and the verdict

What this covers: the definitions every finding uses. Read it before assigning or adjusting a severity. After reading you can calibrate a report so that "critical" means something.
Last checked: 2026-11-13.

## Severity

- **critical**: exploitable now by an anonymous or ordinary user, with direct impact: other users' data read or modified, account takeover, the owner's money spent, or full backend compromise. Blocks launch.
- **high**: a serious weakness that needs one more condition to exploit, or direct impact limited in scope; or an operational gap that makes an incident unrecoverable (no backups for a database with real user data). Blocks launch unless the owner explicitly accepts the risk in writing in the report.
- **medium**: weakens defence in depth or will cause visible failures under normal use. Fix soon after launch; before launch if cheap.
- **low**: hygiene. Batch these.
- **info**: an observation or a question for the owner. Not a defect.

## Confidence

- **confirmed**: the evidence proves the problem (for example a policy with `using (true)` on a table that holds user rows).
- **likely**: the pattern matches and context supports it; a human-style read is needed to be sure.
- **possible**: a heuristic matched. It must be reviewed before it is reported.

## Adjustments (made by the reviewer, explained in the report, never by scanners)

- Raise one level when the affected data is sensitive (health, financial, identity documents, children, precise location, private messages).
- Raise one level when the app is already live with real users.
- Lower one level when a compensating control demonstrably exists. State which one and where.
- Never lower a critical secrets or open-database finding because the app is small. Small apps are found by automated scanners like any other.

## Verdict

- Any open critical: `BLOCKED`.
- No critical, any open high not explicitly accepted: `BLOCKED`.
- No critical or high, open medium: `LAUNCH WITH CAUTION`.
- Otherwise `READY`, always followed by the owner actions still open.

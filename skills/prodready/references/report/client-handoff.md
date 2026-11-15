# Handing the report to a client

What this covers: how agencies and freelancers present the report, scope remediation from it and use a re-run as acceptance. Read it when the reader is a client, not the app's builder. After reading you can turn findings into an agreed piece of work.
Last checked: 2026-11-13.

## Presenting it

Send the HTML report (`render_report.py --format html --name "<Client app>" --lang <code>`). Open the call with the verdict and the three first actions, then the access table, then the owner actions the client must do themselves. Do not walk through every finding.

## Scoping remediation

Group findings by who acts: *Claude or you can fix in code* (fix type `auto` or `assisted`), *client must act in a dashboard* (`owner`), and *needs a decision* (accepted risks, legal text). Estimate effort per group from the report's Effort field; secrets, access rules and payments come first because they block launch.

## Suggested statement of work

1. Scope: the finding IDs in the agreed report, by severity.
2. Deliverables: a branch with one commit per finding, migration files (not applied), a verification table, and updated owner actions.
3. Client responsibilities: rotate keys, apply migrations to development then production, enable backups, configure DNS and email.
4. Out of scope: penetration testing, compliance certification, features, redesign.
5. Acceptance: re-running `scripts/run_all.py --baseline` shows the agreed findings fixed and no new critical or high findings, and the app's build and tests pass.

## Re-running as acceptance evidence

Run `verify_fixes.py --baseline .prodready/findings.json --strict --targets <IDs>`. Attach `.prodready/verification.json` or the Verification section of the report. A finding closed by key rotation is "rotated, confirmed by the owner on <date>", not "removed".

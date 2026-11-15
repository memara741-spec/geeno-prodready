---
description: Fix prodready findings on a branch and verify them. Takes finding IDs or a severity.
argument-hint: "[finding IDs, or critical | high | all]"
---
Use the prodready skill to run phases 5 and 6 (Fix, Verify) for $ARGUMENTS, using `.prodready/findings.json` from the latest audit (run an audit first if it is missing). Follow the fix protocol in `references/workflow.md`: new branch, one commit per finding, migrations written but never applied.

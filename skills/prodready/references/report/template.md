# Report template

What this covers: the twelve sections of `PRODREADY_REPORT.md`, in order. Read it when writing or editing a report. After reading you can produce a report a non-engineer can act on.
Last checked: 2026-11-13.

1. **Header:** app name, date, commit hash, what was audited, what was not, tool version.
2. **Verdict:** `BLOCKED`, `LAUNCH WITH CAUTION` or `READY`, then one sentence of rationale.
3. **The three things to do first:** numbered, one sentence each, linked to the finding.
4. **Summary:** counts by severity and category, number of owner actions open.
5. **Who can access what:** the access matrix and the route table in plain terms; if neither could be built, say why.
6. **Findings:** by severity, then category, in this block:

```markdown
### [CRITICAL] DB-002: Anyone can read and change every row in `orders`
**In plain words:** Anyone on the internet can download or edit all of your customers' orders without logging in.
**Where:** `supabase/migrations/0003_orders.sql:14`
**Evidence:** `create policy "Enable all" on public.orders for all using (true);`
**Why it matters:** ...
**Fix:** ... (one or two sentences)
**Effort:** small · **Who:** Claude can fix this; you apply the migration
**Confidence:** confirmed
```

7. **Owner actions:** a checklist of everything only the human can do, each with a guide link and a time estimate.
8. **Questions for you:** open owner questions that affect the verdict.
9. **What looks good:** three to six specific strengths with evidence. Not flattery: it tells the owner what not to break.
10. **Verification** (after fixes): before and after table.
11. **Launch checklist:** the gate items with status.
12. **Appendix:** detected stack, third-party inventory, scanners run and skipped, false positives dismissed with reasons, ignored findings with reasons, and the limits of this audit.

The "limits of this audit" paragraph is mandatory: the review is automated and source-based, dashboards could not be seen unless stated, and it is not a penetration test or a compliance certification.

Tone: consequences first, mechanics second; no fear language, exclamation marks or blame; numbers over adjectives; every finding has an action; a clean app gets a short report. Write in the user's language; check IDs, code and paths stay as they are.

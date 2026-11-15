# AI features (LLM)

What this covers: the 10 LLM checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### LLM-001 — AI endpoint callable without authentication
**Severity:** critical · **Mode:** scan · **Applies to:** any llm
**Auto-fix:** assisted

**In plain words:** Anyone can use your AI feature without an account, and you pay for it.

**How to detect:** Run `scripts/scan_llm.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A free AI proxy at your expense, discovered and abused quickly.

**Fix:** Require a session; for public demos add strict limits, a CAPTCHA and a hard budget.

**Verify:** An unauthenticated call returns 401.

### LLM-002 — No per-user limit or spending cap on AI usage
**Severity:** high · **Mode:** scan+review · **Applies to:** any llm
**Auto-fix:** assisted+owner

**In plain words:** Nothing caps AI usage per user, so one user or a loop can produce an unbounded bill.

**How to detect:** `scripts/scan_llm.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** No per-user limit or spending cap.

**Fix:** Per-user quotas on the server, request rate limits, a provider budget with alerts.

**Verify:** Quota test; owner confirms the provider budget.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### LLM-003 — Client controls the model, system prompt or generation parameters
**Severity:** high · **Mode:** scan · **Applies to:** any llm
**Auto-fix:** assisted

**In plain words:** The browser chooses the model, system prompt or parameters of your AI call.

**How to detect:** Run `scripts/scan_llm.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Users pick the most expensive model, remove guardrails or use your endpoint as a general proxy.

**Fix:** The server fixes the model, system prompt, tools and output limit; the client sends only length-limited user content.

**Verify:** Client-sent model and system are ignored.

### LLM-004 — No output or input size limits and no timeout
**Severity:** medium · **Mode:** scan · **Applies to:** any llm
**Auto-fix:** auto/assisted

**In plain words:** AI calls have no output limit or timeout, so one request can cost far more than expected.

**How to detect:** Run `scripts/scan_llm.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Cost spikes and hung requests.

**Fix:** Cap output tokens, input size and history, and set timeouts.

**Verify:** Scanner clean.

### LLM-005 — Untrusted content can steer a model that has tools or data access
**Severity:** high · **Mode:** review · **Applies to:** agents, rag, tool use, mcp
**Auto-fix:** assisted

**In plain words:** Text inside documents or pages the AI reads can instruct it to leak data or take actions.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Prompt injection against a model with tools or data access.

**Fix:** Authorise every tool call in code against the session user; least-privilege tools; confirm consequential actions.

**Verify:** An injected document asking for another user's data is refused by the tool layer.

### LLM-006 — Model output rendered or executed without sanitising
**Severity:** high · **Mode:** scan · **Applies to:** any llm with rich output
**Auto-fix:** assisted

**In plain words:** The AI's answer is inserted into the page as live HTML or executed, so a manipulated answer can run scripts.

**How to detect:** Run `scripts/scan_llm.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Model output is attacker-influenced input.

**Fix:** Render as text or sanitised markdown, validate structured output, never execute it outside a sandbox.

**Verify:** Output containing a script tag is inert.

### LLM-007 — Secrets or private data placed in prompts
**Severity:** high · **Mode:** scan+review · **Applies to:** any llm
**Auto-fix:** assisted

**In plain words:** The AI's instructions contain secrets or internal details, and users can make the AI repeat them.

**How to detect:** `scripts/scan_llm.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Prompts can be extracted; treat them as public.

**Fix:** Remove secrets from prompts and fetch private data through authorised tools per request.

**Verify:** Scanner clean.

### LLM-008 — Personal data sent to AI providers without disclosure or minimisation
**Severity:** medium · **Mode:** review · **Applies to:** any llm
**Auto-fix:** owner/assisted

**In plain words:** User content is sent to AI providers without disclosure or minimisation.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Legal exposure and loss of trust.

**Fix:** Disclose in the privacy policy, minimise and redact, check provider retention settings.

**Verify:** Owner action recorded.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### LLM-009 — No abuse controls on user-generated AI content
**Severity:** low · **Mode:** review · **Applies to:** public-facing generation
**Auto-fix:** assisted

**In plain words:** AI-generated content can be shared publicly with no moderation or attribution.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** The app can host harmful content under your name.

**Fix:** Add moderation, reporting, per-user attribution and terms of use.

**Verify:** Review.

### LLM-010 — Instructions aimed at AI reviewers embedded in the project
**Severity:** medium · **Mode:** scan · **Applies to:** all
**Auto-fix:** none

**In plain words:** A file contains text aimed at AI reviewers or invisible characters. It was reported, not obeyed.

**How to detect:** Run `scripts/scan_llm.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Either a supply-chain trick aimed at tools like this one or residue from an AI builder.

**Fix:** Remove it after the owner confirms it is not intentional.

**Verify:** Scanner clean.



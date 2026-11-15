# Secrets and keys (SEC)

What this covers: the 16 SEC checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### SEC-001 — Admin-level backend key reachable from client code
**Severity:** critical · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted+owner

**In plain words:** An admin key for your backend is inside the code every visitor downloads, so anyone can read or change all your data.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A key in the bundle is public. Admin keys bypass every access rule, so the whole database or payment account is exposed.

**Fix:** Move the call behind a server route, action or edge function, read the key from a server-only variable, use the publishable key in the browser, then rotate the key.

**Verify:** Re-run scan_secrets and scan_env; build the app and search the output for the key prefix; nothing must match.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-002 — Secret committed in the current working tree
**Severity:** critical · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted+owner

**In plain words:** A real key is saved in a file that is part of your repository, so anyone who can see the repository has it.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** For a public repository that means everyone; automated harvesters find keys within minutes.

**Fix:** Remove the value, load it from the environment, ignore the file, keep an .env.example with empty values, and rotate the key. Removing it does not un-leak it.

**Verify:** Scanner reports nothing in the tree; `git ls-files` lists no env file with values.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-003 — Secret present in git history
**Severity:** high · **Mode:** scan · **Applies to:** all
**Auto-fix:** owner

**In plain words:** A key you deleted is still readable in your repository's history, to anyone who can clone it.

**How to detect:** Run `scripts/scan_git_history.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Deleting a file in a later commit leaves the secret in history, forks and clones.

**Fix:** Rotate the key first. Rewriting history is optional and disruptive; see owner-actions/purge-git-history.md.

**Verify:** Owner confirms the old key no longer works. Close the finding as rotated, not removed.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-004 — Environment files are not ignored by git
**Severity:** high · **Mode:** scan · **Applies to:** all
**Auto-fix:** auto

**In plain words:** Your .gitignore does not exclude .env files, so the next commit will publish your keys.

**How to detect:** Run `scripts/scan_env.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Env files are where secrets live; the next `git add .` commits them.

**Fix:** Add .env and .env.* (keeping !.env.example) to .gitignore, `git rm --cached` any tracked env file, add an .env.example.

**Verify:** `git check-ignore .env` succeeds and `git ls-files` lists only example env files.

### SEC-005 — Secret stored in a browser-exposed environment variable
**Severity:** critical · **Mode:** scan · **Applies to:** nextjs, vite, cra, expo, sveltekit, nuxt, astro
**Auto-fix:** assisted+owner

**In plain words:** A variable meant to hold a secret has a name that makes the build tool copy it into the code sent to every visitor.

**How to detect:** Run `scripts/scan_env.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Prefixes such as NEXT_PUBLIC_ and VITE_ exist precisely to inline the value into browser JavaScript.

**Fix:** Rename it without the public prefix, move the code that uses it to the server, and rotate the key.

**Verify:** Scanner clean; search the build output for the key prefix.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-006 — Hard-coded credential in source code
**Severity:** high · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted+owner

**In plain words:** A key is typed directly into your source code, so it travels wherever the code goes.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Source is copied, shared with AI tools, pushed and deployed; a literal secret travels with it.

**Fix:** Replace the literal with an environment lookup validated at startup, then rotate the key.

**Verify:** Scanner clean.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-007 — Secrets or server code visible in published source maps or build output
**Severity:** high · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** Your built website or source maps expose original code or a secret key to anyone who looks.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Source maps reveal comments and sometimes inlined values; a key in the bundle is public.

**Fix:** Disable public source maps or upload them privately to your error tracker, and remove any secret from client code.

**Verify:** Config check passes and the build directory contains no secret.

### SEC-008 — No .env.example or documentation of required variables
**Severity:** low · **Mode:** scan · **Applies to:** all
**Auto-fix:** auto

**In plain words:** There is no .env.example, so setting the app up elsewhere is guesswork and people paste real .env files into chats.

**How to detect:** Run `scripts/scan_env.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Deployments fail in confusing ways and real secrets get shared to "share the config".

**Fix:** Generate .env.example from the variables the code reads, empty values, marking which are server-only.

**Verify:** Every variable read in code appears in the example.

### SEC-009 — Secrets, tokens or passwords written to logs
**Severity:** medium · **Mode:** scan+review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** Passwords, tokens or personal data are written to your logs, where many people and services can read them.

**How to detect:** `scripts/scan_secrets.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Logs are widely readable, retained for long and forwarded to third parties.

**Fix:** Remove the value or log an identifier instead of the credential.

**Verify:** Scanner clean on the changed files.

### SEC-010 — Weak, default or placeholder signing secret
**Severity:** critical · **Mode:** scan · **Applies to:** custom-jwt, authjs, express-session, django, flask
**Auto-fix:** assisted+owner

**In plain words:** The secret that signs login sessions is guessable or has a built-in fallback, so anyone can forge a login as any user.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Whoever knows the secret can create a valid session for any account, including an administrator.

**Fix:** Require the variable at startup with no fallback, generate a long random value, store it in the host's secret settings, rotate it.

**Verify:** Scanner clean; the app refuses to start without the variable.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-011 — Test and live credentials mixed, or one set shared by all environments
**Severity:** medium · **Mode:** review · **Applies to:** all
**Auto-fix:** owner

**In plain words:** Test and live credentials are mixed, or one set is shared by all environments.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Testing against production corrupts real data; shipping test keys means payments silently do nothing.

**Fix:** Use separate projects or databases per environment and document which variables differ.

**Verify:** Owner confirms separate values exist for production and preview.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-012 — Browser-visible third-party key has no restrictions
**Severity:** medium · **Mode:** review · **Applies to:** firebase, google-maps, mapbox, algolia
**Auto-fix:** owner

**In plain words:** A public key (maps, Firebase web key and similar) has no restrictions, so others can reuse it on their sites at your cost.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Public keys are meant to be visible, but an unrestricted one can be billed to you.

**Fix:** Restrict by HTTP referrer, app identifier and API scope in the provider console; set quotas and billing alerts.

**Verify:** Owner confirms the restrictions.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-013 — AI provider key used directly from the browser or mobile client
**Severity:** critical · **Mode:** scan · **Applies to:** any llm
**Auto-fix:** assisted+owner

**In plain words:** Your AI provider key is usable from the browser or phone app, so anyone can copy it and spend your money.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** The key is extractable in seconds and usable for unlimited spend on your account.

**Fix:** Create a server endpoint that holds the key, authenticates the caller and enforces limits; rotate the key; set a provider spending limit.

**Verify:** Scanner clean; no provider host in the client bundle.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-014 — Secrets embedded in a mobile app configuration
**Severity:** critical · **Mode:** scan · **Applies to:** expo, react-native, capacitor, flutter
**Auto-fix:** assisted+owner

**In plain words:** A secret is written into the mobile app's configuration, and anyone can download and unpack the app.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** App packages are downloadable and trivially unpacked.

**Fix:** Move privileged calls to a backend and keep only public keys in the app; rotate the key.

**Verify:** Scanner clean.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-015 — Private key or service account file in the repository
**Severity:** critical · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted+owner

**In plain words:** A private key or service account file is in your repository, so whoever has the repository can act as your service.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** It grants full impersonation of the service identity.

**Fix:** Remove the file, ignore it, load it from secret storage, and revoke and reissue the key.

**Verify:** Scanner clean; owner confirms revocation.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### SEC-016 — Public key found in client code (not a leak)
**Severity:** info · **Mode:** scan · **Applies to:** supabase, firebase, stripe, clerk
**Auto-fix:** none

**In plain words:** This is a public-by-design key (anon, publishable, Firebase web config). It is not a leak.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** These keys are meant to be in the browser; safety depends on the access rules behind them.

**Fix:** Nothing to fix. Review the database checks instead.

**Verify:** Not applicable.



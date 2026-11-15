<p align="center">
  <img src="docs/images/geeno-banner.svg" alt="GEENO-PRODREADY" width="100%">
</p>

<p align="center">
  <a href="#quick-start"><b>Quick start</b></a> Â·
  <a href="#how-it-works">How it works</a> Â·
  <a href="#what-it-checks">Checks</a> Â·
  <a href="#install-as-a-claude-skill">Install</a> Â·
  <a href="#faq">FAQ</a> Â·
  <a href="#arabic"><b>Ø§Ù„Ø¹Ø±Ø¨ÙŠØ©</b></a>
</p>

<p align="center">
  <img alt="CI" src="https://github.com/memara741-spec/geeno-prodready/actions/workflows/ci.yml/badge.svg">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-2dd4bf">
  <img alt="python" src="https://img.shields.io/badge/python-3.9%2B-38bdf8">
  <img alt="dependencies" src="https://img.shields.io/badge/dependencies-none-a78bfa">
  <img alt="checks" src="https://img.shields.io/badge/checks-187-fbbf24">
  <img alt="telemetry" src="https://img.shields.io/badge/telemetry-none-34d399">
</p>

<a id="english"></a>

# geeno-prodready

An app that works in the demo is not the same as an app that is safe to launch. **geeno-prodready** is a pre-launch review for apps built with Lovable, Bolt, v0, Replit, Cursor or Claude Code. It reads your project, shows you exactly which file and line is a problem, explains the damage in plain words, fixes what it can on a separate branch, and checks that each fix worked.

It ships as a [Claude](https://claude.com) skill, and the scanners also run on their own from the command line with nothing to install except Python.

<p align="center"><img src="docs/images/problem-solution.svg" alt="The problem and what geeno-prodready does about it" width="100%"></p>

## Quick start

You need Python 3.9 or newer and git. Nothing else.

```bash
git clone https://github.com/memara741-spec/geeno-prodready.git
cd geeno-prodready

# Scan an app and print a short summary
python3 skills/prodready/scripts/run_all.py /path/to/your-app --format summary

# Full scan including git history, saved to a file
python3 skills/prodready/scripts/run_all.py /path/to/your-app --history --out /path/to/your-app/.prodready/findings.json

# Turn that file into a report you can read or send to a client
python3 skills/prodready/scripts/render_report.py /path/to/your-app --format html --out report.html
```

On Windows use `python` instead of `python3`. On the sample app in this repo you can try it right away:

```bash
python3 skills/prodready/scripts/run_all.py fixtures/lovable-supabase-vite --format summary
```

<p align="center"><img src="docs/images/quickstart.svg" alt="Quick start commands" width="100%"></p>

### Command cheat sheet

| I want to | Command |
|---|---|
| See a short summary | `run_all.py <app> --format summary` |
| Save findings as JSON | `run_all.py <app> --out findings.json` |
| Include git history (leaked keys) | add `--history` |
| Only some checks | `--only DB` or `--only SEC-001 --only AUTH` |
| Make CI fail on a critical issue | `run_all.py . --fail-on critical` |
| Upload to GitHub code scanning | `run_all.py . --format sarif --out prodready.sarif` |
| Compare with an earlier scan | `run_all.py <app> --baseline old.json --out new.json` |
| Check that fixes worked | `verify_fixes.py <app> --baseline findings.json` |
| Report in Markdown or HTML | `render_report.py <app> --format md` or `--format html` |
| Report in Arabic layout | `render_report.py <app> --format html --lang ar` |
| Check your own live site (read-only) | `probe_live.py --base-url https://yours --allow-network --i-own-this` |
| Run the project's tests | `python3 -m unittest discover -s tests -t tests` |

All scripts live in `skills/prodready/scripts/`. Every one answers `--help`.

## Install as a Claude skill

The scripts are useful alone, but the full workflow (review, report, fixes, verification) runs inside Claude.

1. **Claude Code plugin** (not tested end to end yet):
   ```bash
   claude plugin marketplace add memara741-spec/geeno-prodready
   claude plugin install prodready@prodready-marketplace
   ```
2. **Skill folder** (the copied folder was run and scans correctly; loading it inside Claude is not tested yet). Copy `skills/prodready` to `~/.claude/skills/prodready` for all projects, or to `.claude/skills/prodready` for one.
3. **Claude apps** (the zip was built, unpacked and run; uploading it to Claude is not tested yet). Run `python3 tools/package.py` and upload `dist/prodready-skill.zip` in the skills settings.

Then open your app in Claude and ask:

> *Is this app ready to launch?*

The plugin also adds `/prodready-audit`, `/prodready-fix` and `/prodready-launch`.

## Why this exists

People now ship real products built with AI tools. The demo works, so the app goes live with real users, real personal data and real payments. A senior engineer would catch a short list of familiar problems in a review. The people who built these apps usually cannot, and "add authentication" or "follow OWASP" is advice they cannot map to their own code.

This project does that review for them and keeps it honest: every finding points at evidence, and a fix only counts once the scanner that found the problem comes back clean.

## What it catches

- A database any visitor can read or change, because row level security is off or the policy says `using (true)`.
- An admin, payment or AI key inside the code that every visitor downloads, or committed to the repository.
- Pages "protected" by hiding a button while the API behind them answers anyone.
- A checkout that trusts the price sent by the browser, and payment webhooks anyone can fake.
- An AI endpoint with no sign-in and no spending cap, which is a free proxy at your expense.
- No backups, no error tracking, no way to roll back, emails that land in spam, no privacy policy.

## How it works

<p align="center"><img src="docs/images/workflow.svg" alt="Seven steps from detection to launch gate" width="100%"></p>

1. **Detect** the framework, backend, database, auth, payments, AI providers, hosting and builder.
2. **Scan** with read-only scripts that return findings with file, line and a redacted snippet.
3. **Review** the logic scripts cannot judge: who may read which data, how identity is decided, how money moves.
4. **Report** with the verdict first and the three things to do before anything else.
5. **Fix** on a new branch, one commit per finding, asking before anything irreversible.
6. **Verify** by re-running the scanners and your own build and tests.
7. **Launch gate**: a checklist that includes what only you can do, such as rotating a key or turning on backups.

### Under the hood

<p align="center"><img src="docs/images/architecture.svg" alt="Architecture" width="100%"></p>

Scanners find candidates and attach evidence. Claude reads each candidate in context and decides whether it is real. That split keeps the false alarms low, which matters, because a false "critical" teaches people to ignore the tool.

### How the verdict is decided

<p align="center"><img src="docs/images/verdict.svg" alt="Verdict decision flow" width="100%"></p>

## What the report looks like

<p align="center"><img src="docs/images/report-preview.svg" alt="Report preview with verdict, first actions and access table" width="100%"></p>

The report opens with the verdict and three actions, then shows an access table (who can read and change each table and route), then the findings, then a checklist of owner actions. A real one, generated from a sample app: [Markdown](docs/demo/sample-report.md) Â· [HTML](docs/demo/sample-report.html).

## What it checks

<p align="center"><img src="docs/images/categories.svg" alt="187 checks in 18 categories" width="100%"></p>

Every check has a plain-words explanation, why it matters, how to fix it and how to verify the fix. The full list is in [`references/checks/INDEX.md`](skills/prodready/references/checks/INDEX.md).

| Area | Examples |
|---|---|
| Secrets | admin key in the browser bundle, key in git history, secret in a `VITE_` variable |
| Auth | route with no authentication, user ID taken from the request, unverified JWT |
| Database | RLS off, `using (true)`, open Firebase rules, public storage bucket |
| API | unsigned webhook, path traversal, SQL built from request text, SSRF |
| Payments | price from the browser, plan granted on the success page, test keys in production |
| AI features | open AI endpoint, client picks the model, model output rendered as HTML |
| Launch | no backups, no error tracking, default favicon, builder badge left in |

Severity means something: **critical** is "an anonymous person can read other people's data, spend your money or take over accounts today". Public keys (Supabase anon, Firebase web config, Stripe publishable) are never reported as leaks.

## Safety

<p align="center"><img src="docs/images/safety-model.svg" alt="Safety model" width="100%"></p>

## Supported stacks

| Stack | Depth |
|---|---|
| Supabase, Firebase | deep: policies, rules, storage, functions |
| Next.js, Vite and React, Express, Prisma, Stripe | good |
| Remix, SvelteKit, Nuxt, Django, Flask, FastAPI, Expo | basic |
| Lovable, Bolt, v0, Replit, IDE agents | detection plus a playbook per builder |

If your stack is not listed, the generic checks (secrets, routes, headers, dependencies, launch polish) still run.

## Configuration

An optional `.prodready.json` in the scanned app:

```json
{
  "exclude": ["legacy/**"],
  "ignore": [{ "fingerprint": "sha256:...", "reason": "public demo table", "by": "owner", "date": "2026-01-01" }],
  "public_tables": ["public.blog_posts"],
  "severity_overrides": { "HDR-004": "info" }
}
```

Ignored findings stay in the output with their reason, so nothing disappears silently.

## Use it in CI

```yaml
# .github/workflows/prodready.yml  (a complete file is in skills/prodready/assets/ci/prodready.yml)
- run: python3 skills/prodready/scripts/run_all.py . --fail-on critical --format sarif --out prodready.sarif
```

Exit code 1 means a confirmed finding at or above the chosen severity.

## Project layout

```text
skills/prodready/      the skill: SKILL.md, scripts/, references/, assets/
commands/  agents/     optional Claude Code plugin extras
fixtures/              nine sample apps with planted problems and expected results
tests/                 49 tests (scanners, report, probe, packaging)
tools/                 maintainer scripts (package, generate references, demo)
evals/                 prompts and a rubric for testing the skill itself
docs/                  decisions, roadmap, authoring guide, images, sample report
```

## Develop

```bash
python3 -m unittest discover -s tests -t tests   # run everything
python3 tools/expect.py                          # recall and false positives per fixture
python3 tools/package.py                         # build dist/prodready-skill.zip
python3 tools/gen_checks.py                      # regenerate the check reference files
```

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/CHECK_AUTHORING.md](docs/CHECK_AUTHORING.md). Report security problems through [SECURITY.md](SECURITY.md). Open work is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Limits

This is a review of your source code. It is not a penetration test, not a compliance certification, and not a substitute for a professional audit if you handle health, financial or children's data. It never scans other people's sites. Settings that exist only in a provider dashboard, such as backups or email DNS, cannot be seen from code, so the report asks you about them.

## FAQ

**Is my Supabase anon key a leak?** No. Anon and publishable keys, the Firebase web config and Stripe publishable keys are meant to be in the browser. They show up as information (SEC-016). What protects your data is the access rules behind them.

**It says RLS is on but still flags my table.** RLS with `using (true)`, or "any signed-in user", is open. Anyone can sign up. The scanner reads the policy, not just the switch.

**Does it send my code anywhere?** No. It runs on your machine and has no telemetry.

**Can it scan a live URL?** Only yours, with two explicit flags, read-only. Most of the work is on source code.

**Will it break my app?** Fixes go on a branch, one commit each. Tighter access rules can break features that quietly depended on open access, so the skill lists the affected code before changing anything. It never applies database changes or merges for you.

**How is this different from my builder's built-in check?** It is independent of the builder, runs locally, gives evidence you can open, re-runs to prove a fix, and covers launch items like backups, email and payments. Use both.

## Author

Created by **MOHAMED IBRAHEM** Â· [MIT License](LICENSE)

---

<a id="arabic"></a>

<div dir="rtl">

# geeno-prodready

Ø§Ù„ØªØ·Ø¨ÙŠÙ‚ Ø§Ù„Ø°ÙŠ ÙŠØ¹Ù…Ù„ ÙÙŠ Ø§Ù„Ø¹Ø±Ø¶ Ø§Ù„ØªØ¬Ø±ÙŠØ¨ÙŠ Ù„ÙŠØ³ Ø¨Ø§Ù„Ø¶Ø±ÙˆØ±Ø© Ø¢Ù…Ù†Ø§Ù‹ Ù„Ù„Ø¥Ø·Ù„Ø§Ù‚. **geeno-prodready** Ù…Ø±Ø§Ø¬Ø¹Ø© Ù…Ø§ Ù‚Ø¨Ù„ Ø§Ù„Ø¥Ø·Ù„Ø§Ù‚ Ù„Ù„ØªØ·Ø¨ÙŠÙ‚Ø§Øª Ø§Ù„Ù…Ø¨Ù†ÙŠØ© Ø¨Ù€ Lovable Ø£Ùˆ Bolt Ø£Ùˆ v0 Ø£Ùˆ Replit Ø£Ùˆ Cursor Ø£Ùˆ Claude Code. ÙŠÙ‚Ø±Ø£ Ù…Ø´Ø±ÙˆØ¹ÙƒØŒ ÙˆÙŠØ¯Ù„Ù‘Ùƒ Ø¹Ù„Ù‰ Ø§Ù„Ù…Ù„Ù ÙˆØ§Ù„Ø³Ø·Ø± Ø§Ù„Ø°ÙŠ ÙÙŠÙ‡ Ø§Ù„Ù…Ø´ÙƒÙ„Ø©ØŒ ÙˆÙŠØ´Ø±Ø­ Ø§Ù„Ø¶Ø±Ø± Ø¨ÙƒÙ„Ø§Ù… Ø¨Ø³ÙŠØ·ØŒ ÙˆÙŠØµÙ„Ø­ Ù…Ø§ ÙŠÙ…ÙƒÙ† Ø¥ØµÙ„Ø§Ø­Ù‡ Ø¹Ù„Ù‰ ÙØ±Ø¹ Ù…Ø³ØªÙ‚Ù„ØŒ Ø«Ù… ÙŠØªØ£ÙƒØ¯ Ø£Ù† ÙƒÙ„ Ø¥ØµÙ„Ø§Ø­ Ù†Ø¬Ø­.

ÙŠØ¹Ù…Ù„ ÙƒÙ…Ù‡Ø§Ø±Ø© (skill) Ù„Ù€ [Claude](https://claude.com)ØŒ ÙƒÙ…Ø§ ØªØ¹Ù…Ù„ Ø§Ù„Ù…Ø§Ø³Ø­Ø§Øª ÙˆØ­Ø¯Ù‡Ø§ Ù…Ù† Ø³Ø·Ø± Ø§Ù„Ø£ÙˆØ§Ù…Ø± ÙˆÙ„Ø§ ØªØ­ØªØ§Ø¬ Ø¥Ù„Ø§ Python.

## ØªØ´ØºÙŠÙ„ Ø³Ø±ÙŠØ¹

Ø§Ù„Ù…Ø·Ù„ÙˆØ¨ Python 3.9 Ø£Ùˆ Ø£Ø­Ø¯Ø« ÙˆgitØŒ Ù„Ø§ Ø´ÙŠØ¡ Ø¢Ø®Ø±.

```bash
git clone https://github.com/memara741-spec/geeno-prodready.git
cd geeno-prodready

# ÙØ­Øµ ØªØ·Ø¨ÙŠÙ‚ ÙˆØ·Ø¨Ø§Ø¹Ø© Ù…Ù„Ø®Øµ Ù‚ØµÙŠØ±
python3 skills/prodready/scripts/run_all.py /path/to/your-app --format summary

# ÙØ­Øµ ÙƒØ§Ù…Ù„ ÙŠØ´Ù…Ù„ ØªØ§Ø±ÙŠØ® git ÙˆØ­ÙØ¸ Ø§Ù„Ù†ØªØ§Ø¦Ø¬ ÙÙŠ Ù…Ù„Ù
python3 skills/prodready/scripts/run_all.py /path/to/your-app --history --out /path/to/your-app/.prodready/findings.json

# ØªØ­ÙˆÙŠÙ„ Ø§Ù„Ù†ØªØ§Ø¦Ø¬ Ø¥Ù„Ù‰ ØªÙ‚Ø±ÙŠØ± ØªÙ‚Ø±Ø¤Ù‡ Ø£Ùˆ ØªØ±Ø³Ù„Ù‡ Ù„Ù„Ø¹Ù…ÙŠÙ„
python3 skills/prodready/scripts/render_report.py /path/to/your-app --format html --lang ar --out report.html
```

Ø¹Ù„Ù‰ Windows Ø§Ø³ØªØ®Ø¯Ù… `python` Ø¨Ø¯Ù„ `python3`. ÙˆÙ„Ù„ØªØ¬Ø±Ø¨Ø© Ø§Ù„ÙÙˆØ±ÙŠØ© Ø¹Ù„Ù‰ ØªØ·Ø¨ÙŠÙ‚ Ù†Ù…ÙˆØ°Ø¬ÙŠ Ø¯Ø§Ø®Ù„ Ø§Ù„Ù…Ø³ØªÙˆØ¯Ø¹:

```bash
python3 skills/prodready/scripts/run_all.py fixtures/lovable-supabase-vite --format summary
```

### Ù…Ù„Ø®Øµ Ø§Ù„Ø£ÙˆØ§Ù…Ø±

| Ø£Ø±ÙŠØ¯ Ø£Ù† | Ø§Ù„Ø£Ù…Ø± |
|---|---|
| Ø£Ø±Ù‰ Ù…Ù„Ø®ØµØ§Ù‹ Ù‚ØµÙŠØ±Ø§Ù‹ | `run_all.py <app> --format summary` |
| Ø£Ø­ÙØ¸ Ø§Ù„Ù†ØªØ§Ø¦Ø¬ JSON | `run_all.py <app> --out findings.json` |
| Ø£ÙØ­Øµ ØªØ§Ø±ÙŠØ® git Ø¨Ø­Ø«Ø§Ù‹ Ø¹Ù† Ù…ÙØ§ØªÙŠØ­ Ù…Ø³Ø±Ù‘Ø¨Ø© | Ø£Ø¶Ù `--history` |
| Ø£Ø´ØºÙ‘Ù„ ÙØ­ÙˆØµØ§Ù‹ Ù…Ø­Ø¯Ø¯Ø© | `--only DB` Ø£Ùˆ `--only SEC-001` |
| Ø£ÙÙØ´Ù„ Ø§Ù„Ù€ CI Ø¹Ù†Ø¯ Ù…Ø´ÙƒÙ„Ø© Ø­Ø±Ø¬Ø© | `run_all.py . --fail-on critical` |
| Ø£ØªØ£ÙƒØ¯ Ø£Ù† Ø§Ù„Ø¥ØµÙ„Ø§Ø­Ø§Øª Ù†Ø¬Ø­Øª | `verify_fixes.py <app> --baseline findings.json` |
| Ø£Ø´ØºÙ‘Ù„ Ø§Ø®ØªØ¨Ø§Ø±Ø§Øª Ø§Ù„Ù…Ø´Ø±ÙˆØ¹ | `python3 -m unittest discover -s tests -t tests` |

## Ø§Ù„ØªØ«Ø¨ÙŠØª ÙƒÙ…Ù‡Ø§Ø±Ø© Ù„Ù€ Claude

1. **Ø¥Ø¶Ø§ÙØ© Claude Code** (Ù„Ù… ØªÙØ¬Ø±ÙŽÙ‘Ø¨ Ù…Ù† Ø§Ù„Ø¨Ø¯Ø§ÙŠØ© Ù„Ù„Ù†Ù‡Ø§ÙŠØ© Ø¨Ø¹Ø¯):
   ```bash
   claude plugin marketplace add memara741-spec/geeno-prodready
   claude plugin install prodready@prodready-marketplace
   ```
2. **Ù…Ø¬Ù„Ø¯ Ø§Ù„Ù…Ù‡Ø§Ø±Ø©** (Ù„Ù… ÙŠÙØ¬Ø±ÙŽÙ‘Ø¨ ÙÙŠ Ø¬Ù„Ø³Ø© Ø­ÙŠØ© Ø¨Ø¹Ø¯): Ø§Ù†Ø³Ø® `skills/prodready` Ø¥Ù„Ù‰ `~/.claude/skills/prodready` Ø£Ùˆ `.claude/skills/prodready`.
3. **ØªØ·Ø¨ÙŠÙ‚Ø§Øª Claude** (Ù„Ù… ØªÙØ¬Ø±ÙŽÙ‘Ø¨ Ø¨Ø¹Ø¯): Ø´ØºÙ‘Ù„ `python3 tools/package.py` ÙˆØ§Ø±ÙØ¹ `dist/prodready-skill.zip` ÙÙŠ Ø¥Ø¹Ø¯Ø§Ø¯Ø§Øª Ø§Ù„Ù…Ù‡Ø§Ø±Ø§Øª.

Ø«Ù… Ø§ÙØªØ­ ØªØ·Ø¨ÙŠÙ‚Ùƒ ÙÙŠ Claude ÙˆØ§Ø³Ø£Ù„: *Ù‡Ù„ Ù‡Ø°Ø§ Ø§Ù„ØªØ·Ø¨ÙŠÙ‚ Ø¬Ø§Ù‡Ø² Ù„Ù„Ø¥Ø·Ù„Ø§Ù‚ØŸ*

## Ù„Ù…Ø§Ø°Ø§ Ù‡Ø°Ø§ Ø§Ù„Ù…Ø´Ø±ÙˆØ¹

ØµØ§Ø± Ø§Ù„Ù†Ø§Ø³ ÙŠØ·Ù„Ù‚ÙˆÙ† Ù…Ù†ØªØ¬Ø§Øª Ø­Ù‚ÙŠÙ‚ÙŠØ© Ø¨ÙÙ†ÙŠØª Ø¨Ø£Ø¯ÙˆØ§Øª Ø§Ù„Ø°ÙƒØ§Ø¡ Ø§Ù„Ø§ØµØ·Ù†Ø§Ø¹ÙŠ. Ø§Ù„Ø¹Ø±Ø¶ Ø§Ù„ØªØ¬Ø±ÙŠØ¨ÙŠ ÙŠØ¹Ù…Ù„ØŒ ÙÙŠØ®Ø±Ø¬ Ø§Ù„ØªØ·Ø¨ÙŠÙ‚ Ø¨Ù…Ø³ØªØ®Ø¯Ù…ÙŠÙ† ÙˆØ¨ÙŠØ§Ù†Ø§Øª Ø´Ø®ØµÙŠØ© ÙˆÙ…Ø¯ÙÙˆØ¹Ø§Øª Ø­Ù‚ÙŠÙ‚ÙŠØ©. Ø§Ù„Ù…Ù‡Ù†Ø¯Ø³ Ø§Ù„Ø®Ø¨ÙŠØ± ÙŠÙ„ØªÙ‚Ø· ÙÙŠ Ø§Ù„Ù…Ø±Ø§Ø¬Ø¹Ø© Ù‚Ø§Ø¦Ù…Ø© Ù‚ØµÙŠØ±Ø© Ù…Ù† Ø§Ù„Ù…Ø´Ø§ÙƒÙ„ Ø§Ù„Ù…Ø¹Ø±ÙˆÙØ©ØŒ Ø£Ù…Ø§ Ø£ØµØ­Ø§Ø¨ Ù‡Ø°Ù‡ Ø§Ù„ØªØ·Ø¨ÙŠÙ‚Ø§Øª ÙØºØ§Ù„Ø¨Ø§Ù‹ Ù„Ø§ ÙŠØ³ØªØ·ÙŠØ¹ÙˆÙ†ØŒ ÙˆÙ†ØµÙŠØ­Ø© Ù…Ø«Ù„ "Ø£Ø¶Ù Ù…ØµØ§Ø¯Ù‚Ø©" Ù„Ø§ ÙŠÙ…ÙƒÙ†Ù‡Ù… Ø±Ø¨Ø·Ù‡Ø§ Ø¨ÙƒÙˆØ¯Ù‡Ù….

Ù‡Ø°Ø§ Ø§Ù„Ù…Ø´Ø±ÙˆØ¹ ÙŠÙ‚ÙˆÙ… Ø¨ØªÙ„Ùƒ Ø§Ù„Ù…Ø±Ø§Ø¬Ø¹Ø© Ù†ÙŠØ§Ø¨Ø© Ø¹Ù†Ù‡Ù…ØŒ ÙˆÙŠØ¨Ù‚Ù‰ ØµØ§Ø¯Ù‚Ø§Ù‹: ÙƒÙ„ Ù†ØªÙŠØ¬Ø© Ù„Ù‡Ø§ Ø¯Ù„ÙŠÙ„ØŒ ÙˆÙ„Ø§ ÙŠÙØ­Ø³Ø¨ Ø§Ù„Ø¥ØµÙ„Ø§Ø­ Ø¥Ù„Ø§ Ø¨Ø¹Ø¯ Ø£Ù† ÙŠØ¹ÙˆØ¯ Ø§Ù„Ù…Ø§Ø³Ø­ Ø§Ù„Ø°ÙŠ Ø§ÙƒØªØ´Ù Ø§Ù„Ù…Ø´ÙƒÙ„Ø© Ù†Ø¸ÙŠÙØ§Ù‹.

## Ù…Ø§Ø°Ø§ ÙŠÙƒØªØ´Ù

- Ù‚Ø§Ø¹Ø¯Ø© Ø¨ÙŠØ§Ù†Ø§Øª ÙŠØ³ØªØ·ÙŠØ¹ Ø£ÙŠ Ø²Ø§Ø¦Ø± Ù‚Ø±Ø§Ø¡ØªÙ‡Ø§ Ø£Ùˆ ØªØ¹Ø¯ÙŠÙ„Ù‡Ø§ØŒ Ù„Ø£Ù† Ø­Ù…Ø§ÙŠØ© Ø§Ù„ØµÙÙˆÙ (RLS) Ù…ØºÙ„Ù‚Ø© Ø£Ùˆ Ø§Ù„Ø³ÙŠØ§Ø³Ø© ØªÙ‚ÙˆÙ„ `using (true)`.
- Ù…ÙØªØ§Ø­ Ø¥Ø¯Ø§Ø±Ø© Ø£Ùˆ Ø¯ÙØ¹ Ø£Ùˆ Ø°ÙƒØ§Ø¡ Ø§ØµØ·Ù†Ø§Ø¹ÙŠ Ø¯Ø§Ø®Ù„ ÙƒÙˆØ¯ ÙŠØ­Ù…Ù‘Ù„Ù‡ ÙƒÙ„ Ø²Ø§Ø¦Ø±ØŒ Ø£Ùˆ Ù…Ø±ÙÙˆØ¹ ÙÙŠ Ø§Ù„Ù…Ø³ØªÙˆØ¯Ø¹.
- ØµÙØ­Ø§Øª "Ù…Ø­Ù…ÙŠØ©" Ø¨Ø¥Ø®ÙØ§Ø¡ Ø²Ø± ÙÙ‚Ø·ØŒ Ø¨ÙŠÙ†Ù…Ø§ Ø§Ù„Ù€ API Ø®Ù„ÙÙ‡Ø§ ÙŠØ¬ÙŠØ¨ Ø£ÙŠ Ø£Ø­Ø¯.
- ØµÙØ­Ø© Ø¯ÙØ¹ ØªØ«Ù‚ Ø¨Ø§Ù„Ø³Ø¹Ø± Ø§Ù„Ù‚Ø§Ø¯Ù… Ù…Ù† Ø§Ù„Ù…ØªØµÙØ­ØŒ Ùˆwebhooks Ù„Ù„Ø¯ÙØ¹ ÙŠØ³ØªØ·ÙŠØ¹ Ø£ÙŠ Ø´Ø®Øµ ØªØ²ÙŠÙŠÙÙ‡Ø§.
- Ù†Ù‚Ø·Ø© Ø°ÙƒØ§Ø¡ Ø§ØµØ·Ù†Ø§Ø¹ÙŠ Ø¨Ù„Ø§ ØªØ³Ø¬ÙŠÙ„ Ø¯Ø®ÙˆÙ„ ÙˆÙ„Ø§ Ø­Ø¯ Ù„Ù„Ø¥Ù†ÙØ§Ù‚ØŒ Ø£ÙŠ ÙˆÙƒÙŠÙ„ Ù…Ø¬Ø§Ù†ÙŠ Ø¹Ù„Ù‰ Ø­Ø³Ø§Ø¨Ùƒ.
- Ù„Ø§ Ù†Ø³Ø® Ø§Ø­ØªÙŠØ§Ø·ÙŠØ© ÙˆÙ„Ø§ ØªØªØ¨Ø¹ Ø£Ø®Ø·Ø§Ø¡ ÙˆÙ„Ø§ Ø±Ø¬ÙˆØ¹ Ù„Ù†Ø³Ø®Ø© Ø³Ø§Ø¨Ù‚Ø©ØŒ ÙˆØ¨Ø±ÙŠØ¯ ÙŠØ°Ù‡Ø¨ Ø¥Ù„Ù‰ Ø§Ù„Ø³Ø¨Ø§Ù…ØŒ ÙˆØ³ÙŠØ§Ø³Ø© Ø®ØµÙˆØµÙŠØ© ØºØ§Ø¦Ø¨Ø©.

## ÙƒÙŠÙ ÙŠØ¹Ù…Ù„

1. **Ø§ÙƒØªØ´Ø§Ù** Ø§Ù„Ù€ framework ÙˆØ§Ù„Ø®Ù„ÙÙŠØ© ÙˆÙ‚Ø§Ø¹Ø¯Ø© Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª ÙˆØ§Ù„Ù…ØµØ§Ø¯Ù‚Ø© ÙˆØ§Ù„Ù…Ø¯ÙÙˆØ¹Ø§Øª ÙˆÙ…Ø²ÙˆØ¯ÙŠ Ø§Ù„Ø°ÙƒØ§Ø¡ Ø§Ù„Ø§ØµØ·Ù†Ø§Ø¹ÙŠ ÙˆØ§Ù„Ø§Ø³ØªØ¶Ø§ÙØ© ÙˆØ£Ø¯Ø§Ø© Ø§Ù„Ø¨Ù†Ø§Ø¡.
2. **Ù…Ø³Ø­** Ø¨Ø³ÙƒØ±Ø¨ØªØ§Øª Ù„Ù„Ù‚Ø±Ø§Ø¡Ø© ÙÙ‚Ø· ØªØ¹ÙŠØ¯ Ø§Ù„Ù†ØªØ§Ø¦Ø¬ Ø¨Ø§Ù„Ù…Ù„Ù ÙˆØ§Ù„Ø³Ø·Ø± ÙˆÙ…Ù‚ØªØ·Ù Ù…ÙØ®ÙÙ‰ Ù…Ù†Ù‡ Ø£ÙŠ Ø³Ø±.
3. **Ù…Ø±Ø§Ø¬Ø¹Ø©** Ø§Ù„Ù…Ù†Ø·Ù‚ Ø§Ù„Ø°ÙŠ Ù„Ø§ ØªØ­ÙƒÙ… Ø¹Ù„ÙŠÙ‡ Ø§Ù„Ø³ÙƒØ±Ø¨ØªØ§Øª: Ù…Ù† ÙŠÙ‚Ø±Ø£ Ø£ÙŠ Ø¨ÙŠØ§Ù†Ø§ØªØŒ ÙˆÙƒÙŠÙ ØªÙØ­Ø¯ÙŽÙ‘Ø¯ Ø§Ù„Ù‡ÙˆÙŠØ©ØŒ ÙˆÙƒÙŠÙ ØªØªØ­Ø±Ùƒ Ø§Ù„Ø£Ù…ÙˆØ§Ù„.
4. **ØªÙ‚Ø±ÙŠØ±** ÙŠØ¨Ø¯Ø£ Ø¨Ø§Ù„Ø­ÙƒÙ… ÙˆØ£ÙˆÙ„ Ø«Ù„Ø§Ø«Ø© Ø£Ø´ÙŠØ§Ø¡ ØªÙØ¹Ù„Ù‡Ø§.
5. **Ø¥ØµÙ„Ø§Ø­** Ø¹Ù„Ù‰ ÙØ±Ø¹ Ø¬Ø¯ÙŠØ¯ØŒ Ø§Ù„ØªØ²Ø§Ù… Ù„ÙƒÙ„ Ù†ØªÙŠØ¬Ø©ØŒ Ù…Ø¹ Ø§Ù„Ø³Ø¤Ø§Ù„ Ù‚Ø¨Ù„ Ø£ÙŠ Ø®Ø·ÙˆØ© Ù„Ø§ Ø±Ø¬Ø¹Ø© ÙÙŠÙ‡Ø§.
6. **ØªØ­Ù‚Ù‚** Ø¨Ø¥Ø¹Ø§Ø¯Ø© Ø§Ù„Ù…Ø³Ø­ ÙˆØªØ´ØºÙŠÙ„ Ø§Ù„Ø¨Ù†Ø§Ø¡ ÙˆØ§Ù„Ø§Ø®ØªØ¨Ø§Ø±Ø§Øª Ø§Ù„Ø®Ø§ØµØ© Ø¨ØªØ·Ø¨ÙŠÙ‚Ùƒ.
7. **Ø¨ÙˆØ§Ø¨Ø© Ø§Ù„Ø¥Ø·Ù„Ø§Ù‚**: Ù‚Ø§Ø¦Ù…Ø© ØªØ´Ù…Ù„ Ù…Ø§ Ù„Ø§ ÙŠÙØ¹Ù„Ù‡ Ø¥Ù„Ø§ Ø£Ù†ØªØŒ Ù…Ø«Ù„ ØªØ¯ÙˆÙŠØ± Ù…ÙØªØ§Ø­ Ø£Ùˆ ØªÙØ¹ÙŠÙ„ Ø§Ù„Ù†Ø³Ø® Ø§Ù„Ø§Ø­ØªÙŠØ§Ø·ÙŠ.

ØªØ¬Ø¯ Ø§Ù„Ø±Ø³ÙˆÙ… Ø§Ù„ØªÙˆØ¶ÙŠØ­ÙŠØ© (Ø§Ù„Ù…Ø¹Ù…Ø§Ø±ÙŠØ©ØŒ Ù‚Ø±Ø§Ø± Ø§Ù„Ø­ÙƒÙ…ØŒ ØªÙˆØ²ÙŠØ¹ Ø§Ù„ÙØ­ÙˆØµØŒ Ù†Ù…ÙˆØ°Ø¬ Ø§Ù„Ø£Ù…Ø§Ù†) ÙÙŠ Ø§Ù„Ù‚Ø³Ù… Ø§Ù„Ø¥Ù†Ø¬Ù„ÙŠØ²ÙŠ Ø£Ø¹Ù„Ø§Ù‡.

## Ø§Ù„Ø­ÙƒÙ… Ø§Ù„Ù†Ù‡Ø§Ø¦ÙŠ

- **BLOCKED**: ØªÙˆØ¬Ø¯ Ù…Ø´ÙƒÙ„Ø© Ø­Ø±Ø¬Ø© Ù…ÙØªÙˆØ­Ø©ØŒ Ø£Ùˆ Ù…Ø´ÙƒÙ„Ø© Ø¹Ø§Ù„ÙŠØ© Ù„Ù… ÙŠÙ‚Ø¨Ù„Ù‡Ø§ ØµØ§Ø­Ø¨ Ø§Ù„ØªØ·Ø¨ÙŠÙ‚ ÙƒØªØ§Ø¨Ø©Ù‹.
- **LAUNCH WITH CAUTION**: ØªØ¨Ù‚Øª Ù…Ø´Ø§ÙƒÙ„ Ù…ØªÙˆØ³Ø·Ø© ÙÙ‚Ø·.
- **READY**: Ù„Ø§ Ø´ÙŠØ¡ Ù…ÙØªÙˆØ­ Ù…Ù† Ù‡Ø°Ù‡ Ø§Ù„Ø¯Ø±Ø¬Ø§ØªØŒ Ù…Ø¹ Ø¨Ù‚Ø§Ø¡ Ø¥Ø¬Ø±Ø§Ø¡Ø§ØªÙƒ Ø£Ù†Øª.

Ø§Ù„Ù…ÙØ§ØªÙŠØ­ Ø§Ù„Ø¹Ø§Ù…Ø© (anon ÙÙŠ Supabase ÙˆØ¥Ø¹Ø¯Ø§Ø¯ Firebase Ù„Ù„ÙˆÙŠØ¨ ÙˆÙ…ÙØªØ§Ø­ Stripe Ø§Ù„Ø¹Ø§Ù…) Ù„Ø§ ØªÙØ¹Ø¯ ØªØ³Ø±ÙŠØ¨Ø§Ù‹ Ø£Ø¨Ø¯Ø§Ù‹.

## Ø§Ù„Ø£Ù…Ø§Ù†

- Ø§Ù„Ù…Ø§Ø³Ø­Ø§Øª Ù„Ù„Ù‚Ø±Ø§Ø¡Ø© ÙÙ‚Ø·ØŒ ÙˆÙ„Ø§ ØªÙ†ÙÙ‘Ø° ÙƒÙˆØ¯Ø§Ù‹ Ù…Ù† Ù…Ø´Ø±ÙˆØ¹Ùƒ.
- ØªÙØ®ÙÙ‰ Ø§Ù„Ø£Ø³Ø±Ø§Ø± Ø¯Ø§Ø®Ù„ Ø¨Ù†Ø§Ø¡ Ø§Ù„Ù†ØªÙŠØ¬Ø© Ù†ÙØ³Ù‡ØŒ ÙÙ„Ø§ ØªØ­Ù…Ù„ Ø§Ù„Ù†ØªÙŠØ¬Ø© Ù…ÙØªØ§Ø­Ø§Ù‹ ÙƒØ§Ù…Ù„Ø§Ù‹. ÙˆØ§Ù„Ø§Ø®ØªØ¨Ø§Ø±Ø§Øª ØªØªØ­Ù‚Ù‚ Ù…Ù† Ø°Ù„Ùƒ.
- Ù„Ø§ Ø´Ø¨ÙƒØ© Ø§ÙØªØ±Ø§Ø¶ÙŠØ§Ù‹. Ø§Ù„Ø³ÙƒØ±Ø¨Øª Ø§Ù„ÙˆØ­ÙŠØ¯ Ø§Ù„Ø°ÙŠ ÙŠØ³ØªØ®Ø¯Ù…Ù‡Ø§ `probe_live.py`ØŒ ÙˆØ¨Ø¹Ù„Ù…ÙŠÙ† ØµØ±ÙŠØ­ÙŠÙ† ÙˆØ·Ù„Ø¨Ø§Øª Ù‚Ø±Ø§Ø¡Ø© ÙÙ‚Ø· (40 ÙƒØ­Ø¯ Ø£Ù‚ØµÙ‰) Ø¥Ù„Ù‰ Ù†Ø´Ø±Ùƒ Ø£Ù†Øª.
- Ø§Ù„Ø¥ØµÙ„Ø§Ø­Ø§Øª Ø¹Ù„Ù‰ ÙØ±Ø¹ Ù…Ø³ØªÙ‚Ù„ØŒ ÙˆÙ…Ù„ÙØ§Øª Ø§Ù„Ù€ migration ØªÙÙƒØªØ¨ ÙˆÙ„Ø§ ØªÙØ·Ø¨ÙŽÙ‘Ù‚ØŒ ÙˆÙ„Ø§ ÙŠÙØ¯Ù…Ø¬ Ø´ÙŠØ¡ Ø¨Ø¯Ù„Ø§Ù‹ Ù…Ù†Ùƒ.
- Ø£ÙŠ Ù†Øµ ÙÙŠ Ù…Ø´Ø±ÙˆØ¹Ùƒ ÙŠØ£Ù…Ø± Ø§Ù„Ù…Ø±Ø§Ø¬Ø¹ Ø¨Ø¹Ø¯Ù… Ø§Ù„Ø¥Ø¨Ù„Ø§Øº ÙŠÙØ¨Ù„ÙŽÙ‘Øº Ø¹Ù†Ù‡ (LLM-010) ÙˆÙ„Ø§ ÙŠÙØ·Ø§Ø¹.
- Ù…ÙƒØªØ¨Ø© Python Ø§Ù„Ù‚ÙŠØ§Ø³ÙŠØ© ÙÙ‚Ø·ØŒ Ø¨Ù„Ø§ telemetryØŒ ÙˆÙ„Ø§ ÙŠÙØ±ÙØ¹ Ø´ÙŠØ¡.

## Ø§Ù„Ø­Ø¯ÙˆØ¯

Ù‡Ø°Ù‡ Ù…Ø±Ø§Ø¬Ø¹Ø© Ù„ÙƒÙˆØ¯ Ù…ØµØ¯Ø±Ùƒ. Ù„ÙŠØ³Øª Ø§Ø®ØªØ¨Ø§Ø± Ø§Ø®ØªØ±Ø§Ù‚ ÙˆÙ„Ø§ Ø´Ù‡Ø§Ø¯Ø© Ø§Ù…ØªØ«Ø§Ù„ØŒ ÙˆÙ„Ø§ ØªØºÙ†ÙŠ Ø¹Ù† ØªØ¯Ù‚ÙŠÙ‚ Ø§Ø­ØªØ±Ø§ÙÙŠ Ø¥Ù† ÙƒÙ†Øª ØªØªØ¹Ø§Ù…Ù„ Ù…Ø¹ Ø¨ÙŠØ§Ù†Ø§Øª ØµØ­ÙŠØ© Ø£Ùˆ Ù…Ø§Ù„ÙŠØ© Ø£Ùˆ Ø¨ÙŠØ§Ù†Ø§Øª Ø£Ø·ÙØ§Ù„. ÙˆÙ„Ø§ ØªÙØ­Øµ Ù…ÙˆØ§Ù‚Ø¹ Ø§Ù„Ø¢Ø®Ø±ÙŠÙ† Ø£Ø¨Ø¯Ø§Ù‹. Ø§Ù„Ø¥Ø¹Ø¯Ø§Ø¯Ø§Øª Ø§Ù„Ù…ÙˆØ¬ÙˆØ¯Ø© ÙÙŠ Ù„ÙˆØ­Ø§Øª Ø§Ù„Ù…Ø²ÙˆØ¯ÙŠÙ† ÙÙ‚Ø·ØŒ ÙƒØ§Ù„Ù†Ø³Ø® Ø§Ù„Ø§Ø­ØªÙŠØ§Ø·ÙŠ ÙˆDNS Ø§Ù„Ø¨Ø±ÙŠØ¯ØŒ Ù„Ø§ ØªÙØ±Ù‰ Ù…Ù† Ø§Ù„ÙƒÙˆØ¯ØŒ Ù„Ø°Ù„Ùƒ ÙŠØ³Ø£Ù„Ùƒ Ø§Ù„ØªÙ‚Ø±ÙŠØ± Ø¹Ù†Ù‡Ø§.

## Ø£Ø³Ø¦Ù„Ø© Ø´Ø§Ø¦Ø¹Ø©

**Ù‡Ù„ Ù…ÙØªØ§Ø­ anon ØªØ³Ø±ÙŠØ¨ØŸ** Ù„Ø§. Ù…ÙØ§ØªÙŠØ­ anon Ùˆpublishable ÙˆØ¥Ø¹Ø¯Ø§Ø¯ Firebase Ù„Ù„ÙˆÙŠØ¨ ÙˆÙ…ÙØªØ§Ø­ Stripe Ø§Ù„Ø¹Ø§Ù… Ù…ØµÙ…Ù…Ø© Ù„ØªÙƒÙˆÙ† ÙÙŠ Ø§Ù„Ù…ØªØµÙØ­ØŒ ÙˆØªØ¸Ù‡Ø± ÙƒÙ…Ø¹Ù„ÙˆÙ…Ø© (SEC-016). Ù…Ø§ ÙŠØ­Ù…ÙŠ Ø¨ÙŠØ§Ù†Ø§ØªÙƒ Ù‡Ùˆ Ù‚ÙˆØ§Ø¹Ø¯ Ø§Ù„ÙˆØµÙˆÙ„ Ø®Ù„ÙÙ‡Ø§.

**ÙŠÙ‚ÙˆÙ„ Ø¥Ù† RLS Ù…ÙØ¹Ù‘Ù„ ÙˆÙ…Ø¹ Ø°Ù„Ùƒ ÙŠØ¨Ù„Ù‘Øº Ø¹Ù† Ø§Ù„Ø¬Ø¯ÙˆÙ„ØŸ** RLS Ù…Ø¹ `using (true)` Ø£Ùˆ "Ø£ÙŠ Ù…Ø³ØªØ®Ø¯Ù… Ù…Ø³Ø¬Ù‘Ù„" ÙŠØ¹Ù†ÙŠ Ø¬Ø¯ÙˆÙ„Ø§Ù‹ Ù…ÙØªÙˆØ­Ø§Ù‹ØŒ Ù„Ø£Ù† Ø§Ù„ØªØ³Ø¬ÙŠÙ„ Ù…ØªØ§Ø­ Ù„Ù„Ø¬Ù…ÙŠØ¹. Ø§Ù„Ù…Ø§Ø³Ø­ ÙŠÙ‚Ø±Ø£ Ø§Ù„Ø³ÙŠØ§Ø³Ø© ÙˆÙ„ÙŠØ³ Ø§Ù„Ù…ÙØªØ§Ø­ ÙÙ‚Ø·.

**Ù‡Ù„ ÙŠØ±Ø³Ù„ ÙƒÙˆØ¯ÙŠ Ø¥Ù„Ù‰ Ø£ÙŠ Ù…ÙƒØ§Ù†ØŸ** Ù„Ø§. ÙŠØ¹Ù…Ù„ Ø¹Ù„Ù‰ Ø¬Ù‡Ø§Ø²Ùƒ Ø¨Ù„Ø§ telemetry.

**Ù‡Ù„ Ø³ÙŠÙƒØ³Ø± ØªØ·Ø¨ÙŠÙ‚ÙŠØŸ** Ø§Ù„Ø¥ØµÙ„Ø§Ø­Ø§Øª Ø¹Ù„Ù‰ ÙØ±Ø¹ Ù…Ø³ØªÙ‚Ù„ØŒ Ø§Ù„ØªØ²Ø§Ù… Ù„ÙƒÙ„ Ù†ØªÙŠØ¬Ø©. ØªØ´Ø¯ÙŠØ¯ Ù‚ÙˆØ§Ø¹Ø¯ Ø§Ù„ÙˆØµÙˆÙ„ Ù‚Ø¯ ÙŠÙƒØ³Ø± Ù…ÙŠØ²Ø§Øª ÙƒØ§Ù†Øª ØªØ¹ØªÙ…Ø¯ Ø¯ÙˆÙ† Ø£Ù† ØªØ¯Ø±ÙŠ Ø¹Ù„Ù‰ Ø§Ù„ÙˆØµÙˆÙ„ Ø§Ù„Ù…ÙØªÙˆØ­ØŒ Ù„Ø°Ù„Ùƒ ØªØ¹Ø±Ø¶ Ø§Ù„Ù…Ù‡Ø§Ø±Ø© Ø§Ù„ÙƒÙˆØ¯ Ø§Ù„Ù…ØªØ£Ø«Ø± Ù‚Ø¨Ù„ Ø£ÙŠ ØªØºÙŠÙŠØ±. ÙˆÙ„Ø§ ØªØ·Ø¨Ù‘Ù‚ ØªØºÙŠÙŠØ±Ø§Øª Ù‚Ø§Ø¹Ø¯Ø© Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª ÙˆÙ„Ø§ ØªØ¯Ù…Ø¬ Ø¨Ø¯Ù„Ø§Ù‹ Ù…Ù†Ùƒ.

**Ø¨Ù…Ø§Ø°Ø§ ÙŠØ®ØªÙ„Ù Ø¹Ù† ÙØ­Øµ Ø§Ù„Ø£Ù…Ø§Ù† Ø§Ù„Ù…Ø¯Ù…Ø¬ ÙÙŠ Ø£Ø¯Ø§Ø© Ø§Ù„Ø¨Ù†Ø§Ø¡ØŸ** Ù…Ø³ØªÙ‚Ù„ Ø¹Ù†Ù‡Ø§ØŒ ÙŠØ¹Ù…Ù„ Ù…Ø­Ù„ÙŠØ§Ù‹ØŒ ÙŠØ¹Ø·ÙŠ Ø£Ø¯Ù„Ø© ØªÙØªØ­Ù‡Ø§ Ø¨Ù†ÙØ³ÙƒØŒ ÙŠØ¹ÙŠØ¯ Ø§Ù„ÙØ­Øµ Ù„ÙŠØ«Ø¨Øª Ø£Ù† Ø§Ù„Ø¥ØµÙ„Ø§Ø­ Ù†Ø¬Ø­ØŒ ÙˆÙŠØºØ·ÙŠ Ø¨Ù†ÙˆØ¯ Ø§Ù„Ø¥Ø·Ù„Ø§Ù‚ ÙƒØ§Ù„Ù†Ø³Ø® Ø§Ù„Ø§Ø­ØªÙŠØ§Ø·ÙŠ ÙˆØ§Ù„Ø¨Ø±ÙŠØ¯ ÙˆØ§Ù„Ù…Ø¯ÙÙˆØ¹Ø§Øª. Ø§Ø³ØªØ®Ø¯Ù… Ø§Ù„Ø§Ø«Ù†ÙŠÙ†.

## Ø§Ù„Ù…Ø¤Ù„Ù

Ù…Ù† Ø¥Ù†Ø´Ø§Ø¡ **MOHAMED IBRAHEM** Â· Ø§Ù„ØªØ±Ø®ÙŠØµ [MIT](LICENSE)

</div>

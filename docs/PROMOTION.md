# Launch posts (drafts)

Honest numbers only: 235 checks, 71 tests, eleven sample apps, no dependencies. Say what is not tested yet.

## Show HN / Reddit (r/ClaudeAI, r/LovableDev, r/SideProject)

**Title:** I built a pre-launch security review for AI-built apps (Lovable, Bolt, v0, Cursor). It shows the file and line, then verifies the fix.

I kept seeing apps built with AI tools go live with an open Supabase table, an OpenAI key in the browser bundle, or a checkout that trusts the price from the client. The builders are not security engineers, and "follow OWASP" does not help them.

geeno-prodready is a Claude skill plus a set of read-only Python scanners (standard library only, no telemetry). It detects your stack, reports findings with evidence (file, line, redacted snippet), explains each in plain words, fixes on a branch, and re-runs the scanner to prove the fix. Public keys like the Supabase anon key are not reported as leaks.

Not done yet: a full headless run on a real app, and uploading the zip to the Claude apps. Feedback on false positives is the most useful thing you can send.

https://github.com/memara741-spec/geeno-prodready

## X / LinkedIn (English)

Your AI-built app works in the demo. Is it safe to launch?

geeno-prodready reads your project, shows the exact file and line of each problem (open database, leaked key, unsigned payment webhook), explains it in plain words, fixes it on a branch, and re-checks. Runs locally. No dependencies. MIT.

https://github.com/memara741-spec/geeno-prodready

## X / LinkedIn (العربية)

تطبيقك المبني بالذكاء الاصطناعي يعمل في العرض التجريبي. هل هو آمن للإطلاق؟

geeno-prodready يقرأ مشروعك ويدلّك على الملف والسطر لكل مشكلة (قاعدة بيانات مفتوحة، مفتاح مسرّب، webhook دفع غير موقّع)، ويشرحها بكلام بسيط، ويصلحها على فرع، ثم يعيد الفحص. يعمل محلياً بلا اعتماديات. MIT.

https://github.com/memara741-spec/geeno-prodready

## Where to share

Anthropic's Claude Code plugin directory (follow its submission steps), Awesome-lists for Claude skills and for AI security, dev.to and Hashnode (one article: "10 things I found auditing a Lovable app"), the Lovable, Bolt and Replit community forums, and YouTube or Shorts with a 60-second screen recording of a scan.

# The first hour of an incident

What this covers: what to do when the audit finds that a live app is exposed. Read it when a critical finding affects a live app. After reading you can contain, assess and recover calmly.
Last checked: 2026-11-13. This is practical guidance, not legal advice.

1. **Contain.** Rotate the exposed key (`rotate-keys.md`). If the database is open, switch on row level security or lock the rules to deny-all right now, even if features break; a broken app is better than an open one. If a public file leaked, make it private.
2. **Preserve evidence.** Export provider and host logs before they expire. Note the time you found the problem and the time of the commit or deploy that introduced it.
3. **Assess.** Which data was reachable? Which users? Since when? Check access logs and provider usage for requests you do not recognise, and for unexpected cost.
4. **Decide on notification.** If personal data was exposed, speak to a lawyer or your data protection contact before sending anything; notification duties and deadlines depend on where your users live.
5. **Fix properly.** Use the prodready fix protocol on a branch; verify with the scanner and a cross-user test.
6. **Write down what happened:** timeline, cause, impact, what changed, what you will do to prevent it. Keep it factual.

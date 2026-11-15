# Writing the "In plain words" line

What this covers: how to explain a finding to someone who is not an engineer. Read it before writing or editing any finding. After reading you can write one sentence that names who, what and what they can do.
Last checked: 2026-11-13.

Rules: name the actor ("anyone on the internet", "any signed-up user"), name the asset ("your customers' email addresses"), name the action ("download", "change", "delete", "spend"). No jargon in that sentence. State the consequence once, without drama.

| Finding | Bad | Good |
|---|---|---|
| DB-001 | RLS is disabled on public.profiles. | Anyone on the internet can read and change every user profile, because the table has no access rules switched on. |
| DB-002 | Policy uses USING (true). | Anyone can read and change every order without signing in; the rule is on but lets everyone through. |
| DB-003 | Policy lacks ownership scoping. | Any signed-up user can read every message, not just their own. Anyone can sign up, so this protects nothing. |
| DB-010 | Firestore rules permit unauthenticated access. | Anyone can read and change your whole database without an account. |
| SEC-001 | Service key in client bundle. | An admin key for your backend is inside the code every visitor downloads. |
| SEC-013 | LLM key exposed client-side. | Anyone can copy your AI key from the website and spend your money. |
| SEC-003 | Secret in git history. | A key you deleted is still readable in your repository's history. |
| AUTH-002 | Unauthenticated route. | Anyone can call this address and it never checks who is asking. |
| AUTH-004 | Client-supplied user ID trusted. | The server believes whichever user ID the caller sends, so changing one field means acting as anyone. |
| AUTH-013 | Role in user_metadata. | Users can make themselves administrators with one request. |
| API-005 | IDOR. | A signed-in user can change the ID in a request and see someone else's record. |
| API-007 | Webhook lacks signature check. | Anyone can send fake events and the app believes them. |
| PAY-001 | Client-controlled amount. | The buyer's browser decides the price, so anyone can pay what they like. |
| PAY-002 | Webhook unverified. | Anyone can send a fake "payment succeeded" message and get paid access free. |
| PAY-003 | Entitlement on redirect. | Opening the thank-you page grants the paid plan without paying. |
| LLM-001 | Public inference endpoint. | Anyone can use your AI feature without an account, and you pay for every request. |
| LLM-003 | Client controls model parameters. | The browser can pick the most expensive model and remove your instructions. |
| FE-001 | Unsanitised HTML sink. | A script posted by one user would run in every other visitor's browser. |
| DB-016 | No backups. | If your data is lost or deleted, there may be no way to get it back. |
| MAIL-001 | Missing SPF/DKIM. | Your verification emails may land in spam, so new users cannot finish signing up. |

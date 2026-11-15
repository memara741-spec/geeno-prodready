# Fixture: lovable-supabase-vite

**Story.** Layla runs a neighbourhood buy-and-sell group and built "Souq Local", a small marketplace, in
Lovable over a weekend. It is a Vite + React single-page app talking straight to Supabase from the browser.
Sellers post listings, buyers place orders and message sellers, and sellers upload an identity document to
get a "verified" badge. Lovable generated the tables and two edge functions. She is about to share the link
in the group chat.

**What is planted.** Row level security is off on `profiles`; `orders` has a `using (true)` policy;
`messages` is readable by any signed-in user; `listings` accepts inserts for any owner; the identity
document bucket is public; an OpenAI key sits in a `VITE_` variable and is used from the browser; an edge
function uses the service-role key and trusts `user_id` from the body; JWT verification is off for both
edge functions; `.env` is committed; email confirmations are off; the builder's default title, badge script
and README are still there; there is no error boundary. See `expected.json` for the full list by check ID.

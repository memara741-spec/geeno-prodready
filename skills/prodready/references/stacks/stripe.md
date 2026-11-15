# Stripe and other payment providers

What this covers: key types, hosted checkout, server-side prices, webhook verification, idempotency and go-live.
Read it when: `payments: stripe` (or Paddle, Lemon Squeezy, PayPal, Razorpay).
After reading you can: check the four rules and fix payment flows.
Last checked: 2026-11-13.
Sources: https://docs.stripe.com/webhooks

## How this stack works
The browser starts a checkout; the provider takes payment; the provider sends signed events to your webhook; your server grants access from those events.

## What is public and what is secret
Secret (`sk_`), restricted (`rk_`) and webhook (`whsec_`) keys are secret; `pk_` publishable keys are public.

## The failure modes AI tools produce here
Amount or `priceId` from the request (PAY-001); webhook parsed as JSON with no verification (PAY-002); success page grants access (PAY-003); no event-id record (PAY-004); customer or subscription ID from the client (PAY-007); test keys in production (PAY-008); card fields in your own form (PAY-009).

## How to review it
Checkout and portal routes, the webhook route, any success route, `.env.production`, entitlement checks on paid features.

## Correct patterns
```ts
// Verify with the RAW body and the endpoint secret; reject on failure
const raw = await request.text();
const event = stripe.webhooks.constructEvent(raw, request.headers.get('stripe-signature')!, process.env.STRIPE_WEBHOOK_SECRET!);
// record event.id with a unique constraint, then grant access from the verified event
```
Stripe signs with HMAC-SHA256 over `timestamp.payload` in the `Stripe-Signature` header; official libraries use a default 5 minute tolerance (never 0); events can be duplicated and are not ordered, so track event IDs. Return 2xx quickly. Source: https://docs.stripe.com/webhooks
The same four rules apply to every provider: server-side prices, verified webhooks, fulfilment on verified events, idempotent handlers. Handle for subscriptions: checkout completed, subscription updated and deleted, invoice payment failed.

## How to test it
`stripe listen --forward-to localhost:3000/api/webhooks/stripe`; send an unsigned request (expect 400); replay an event (no extra effect); tamper with the amount (ignored).

## Owner dashboard settings to confirm
Live keys only in production; restricted keys; webhook endpoint secret per environment; one real low-value purchase, then refund.

## Checks this playbook supports
PAY-001 to PAY-011, API-007.

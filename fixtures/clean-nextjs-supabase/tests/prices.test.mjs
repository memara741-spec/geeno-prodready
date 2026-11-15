import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const checkout = readFileSync(new URL("../app/api/checkout/route.ts", import.meta.url), "utf8");
const webhook = readFileSync(new URL("../app/api/webhooks/stripe/route.ts", import.meta.url), "utf8");

test("checkout never reads a price or an amount from the request body", () => {
  assert.doesNotMatch(checkout, /unit_amount|parsed\.data\.price|body\.amount/);
  assert.match(checkout, /priceForPlan\(parsed\.data\.plan\)/);
});

test("checkout requires a verified user before doing anything else", () => {
  assert.ok(checkout.indexOf("getVerifiedUser()") < checkout.indexOf("stripe().checkout"));
});

test("webhook verifies the signature on the raw body and records the event id", () => {
  assert.match(webhook, /constructEvent\(rawBody, signature/);
  assert.ok(webhook.indexOf("constructEvent") < webhook.indexOf('from("subscriptions")'));
  assert.match(webhook, /stripe_events/);
});

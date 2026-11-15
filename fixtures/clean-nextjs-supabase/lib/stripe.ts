import "server-only";
import Stripe from "stripe";
import { env } from "@/lib/env";

let client: Stripe | undefined;

export function stripe(): Stripe {
  if (!client) client = new Stripe(env().STRIPE_SECRET_KEY, { timeout: 10000, maxNetworkRetries: 2 });
  return client;
}

// The only prices a customer can buy. The browser sends a plan name, never a price or an amount.
export function priceForPlan(plan: "pro_monthly"): string {
  const prices = { pro_monthly: env().STRIPE_PRICE_PRO_MONTHLY } as const;
  return prices[plan];
}

import type Stripe from "stripe";
import { env } from "@/lib/env";
import { stripe } from "@/lib/stripe";
import { createAdminClient } from "@/lib/supabase/admin";

export async function POST(request: Request) {
  const signature = request.headers.get("stripe-signature");
  const rawBody = await request.text();
  if (!signature) return Response.json({ error: "Missing signature" }, { status: 400 });

  let event: Stripe.Event;
  try {
    event = stripe().webhooks.constructEvent(rawBody, signature, env().STRIPE_WEBHOOK_SECRET);
  } catch {
    return Response.json({ error: "Invalid signature" }, { status: 400 });
  }

  const admin = createAdminClient();

  // Record the event ID first. The unique constraint makes a redelivered event a no-op.
  const { error: seen } = await admin.from("stripe_events").insert({ id: event.id, type: event.type });
  if (seen) return Response.json({ received: true, duplicate: true });

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    if (session.client_reference_id && typeof session.subscription === "string") {
      const subscription = await stripe().subscriptions.retrieve(session.subscription);
      await admin.from("subscriptions").upsert({
        user_id: session.client_reference_id,
        stripe_customer_id: String(session.customer),
        stripe_subscription_id: subscription.id,
        status: subscription.status,
      });
    }
  }

  if (event.type === "customer.subscription.updated" || event.type === "customer.subscription.deleted") {
    const subscription = event.data.object;
    await admin.from("subscriptions").update({ status: subscription.status }).eq("stripe_subscription_id", subscription.id);
  }

  return Response.json({ received: true });
}

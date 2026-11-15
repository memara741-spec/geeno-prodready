import { NextResponse } from "next/server";
import { stripe } from "@/lib/stripe";
import { createClient } from "@/lib/supabase/server";

export async function POST(req: Request) {
  const supabase = await createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { priceId, amount } = await req.json();

  const checkout = await stripe.checkout.sessions.create({
    mode: "payment",
    customer_email: session.user.email,
    line_items: [
      { price: priceId, quantity: 1 },
      { price_data: { currency: "usd", product_data: { name: "Setup fee" }, unit_amount: amount }, quantity: 1 },
    ],
    success_url: "http://localhost:3000/success?session_id={CHECKOUT_SESSION_ID}",
    cancel_url: "http://localhost:3000/pricing",
  });

  return NextResponse.json({ url: checkout.url });
}

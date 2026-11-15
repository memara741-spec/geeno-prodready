import { z } from "zod";
import { env } from "@/lib/env";
import { checkRateLimit } from "@/lib/rate-limit";
import { priceForPlan, stripe } from "@/lib/stripe";
import { getVerifiedUser } from "@/lib/supabase/server";

const bodySchema = z.object({ plan: z.literal("pro_monthly") });

export async function POST(request: Request) {
  const user = await getVerifiedUser();
  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });

  if (!(await checkRateLimit(`checkout:${user.id}`, 5, 60))) {
    return Response.json({ error: "Too many requests" }, { status: 429 });
  }

  const parsed = bodySchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return Response.json({ error: "Invalid request" }, { status: 400 });

  const session = await stripe().checkout.sessions.create({
    mode: "subscription",
    client_reference_id: user.id,
    customer_email: user.email,
    line_items: [{ price: priceForPlan(parsed.data.plan), quantity: 1 }],
    success_url: `${env().NEXT_PUBLIC_SITE_URL}/dashboard?checkout=done`,
    cancel_url: `${env().NEXT_PUBLIC_SITE_URL}/dashboard`,
  });

  return Response.json({ url: session.url });
}

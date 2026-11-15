import { NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase/admin";

export async function POST(req: Request) {
  const event = await req.json();

  if (event.type === "checkout.session.completed") {
    const email = event.data.object.customer_email;
    const { data } = await supabaseAdmin.from("profiles").select("id").eq("email", email).single();
    if (data) {
      await supabaseAdmin.auth.admin.updateUserById(data.id, { user_metadata: { plan: "pro" } });
    }
  }

  return NextResponse.json({ received: true });
}

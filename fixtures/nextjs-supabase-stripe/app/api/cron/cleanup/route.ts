import { NextResponse } from "next/server";
import { supabaseAdmin } from "@/lib/supabase/admin";

export async function GET() {
  const cutoff = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
  await supabaseAdmin.from("events").delete().lt("created_at", cutoff);
  return NextResponse.json({ ok: true });
}

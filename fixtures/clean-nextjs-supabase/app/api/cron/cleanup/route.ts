import { timingSafeEqual } from "node:crypto";
import { env } from "@/lib/env";
import { createAdminClient } from "@/lib/supabase/admin";

function authorised(request: Request): boolean {
  const given = Buffer.from(request.headers.get("authorization") ?? "");
  const expected = Buffer.from(`Bearer ${env().CRON_SECRET}`);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

export async function GET(request: Request) {
  if (!authorised(request)) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const cutoff = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
  const admin = createAdminClient();
  const { error } = await admin.from("stripe_events").delete().lt("received_at", cutoff);
  if (error) return Response.json({ error: "Cleanup failed" }, { status: 500 });
  return Response.json({ ok: true });
}

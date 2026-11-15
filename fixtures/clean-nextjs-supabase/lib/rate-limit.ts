import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";

// Fixed-window rate limit stored in Postgres, so it works across serverless instances.
export async function checkRateLimit(key: string, limit: number, windowSeconds: number): Promise<boolean> {
  const admin = createAdminClient();
  const { data, error } = await admin.rpc("hit_rate_limit", { p_key: key, p_limit: limit, p_window_seconds: windowSeconds });
  if (error) return false;
  return data === true;
}

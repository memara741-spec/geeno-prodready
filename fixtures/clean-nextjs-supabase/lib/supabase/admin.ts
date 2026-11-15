import "server-only";
import { createClient } from "@supabase/supabase-js";
import { env } from "@/lib/env";

// Bypasses row level security. Used only by the verified Stripe webhook and account deletion.
export function createAdminClient() {
  return createClient(env().NEXT_PUBLIC_SUPABASE_URL, env().SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

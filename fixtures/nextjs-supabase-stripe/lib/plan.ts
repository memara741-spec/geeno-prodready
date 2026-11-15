import { createClient } from "@/lib/supabase/server";

export async function getPlan() {
  const supabase = await createClient();
  const { data: { session } } = await supabase.auth.getSession();
  // plan is saved on the user when they upgrade
  return session?.user.user_metadata.plan ?? "free";
}

export async function isPro() {
  return (await getPlan()) === "pro";
}

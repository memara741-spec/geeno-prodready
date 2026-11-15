import { supabaseAdmin } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";

export default async function Success({ searchParams }: { searchParams: Promise<{ session_id?: string }> }) {
  const { session_id } = await searchParams;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (user && session_id) {
    // payment done, upgrade the account
    await supabaseAdmin.auth.admin.updateUserById(user.id, { user_metadata: { plan: "pro" } });
  }

  return <h1>Thanks! Your account is now Pro.</h1>;
}

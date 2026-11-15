import { createAdminClient } from "@/lib/supabase/admin";
import { getVerifiedUser } from "@/lib/supabase/server";

// Deletes the signed-in user's account. Boards and subscriptions are removed by ON DELETE CASCADE.
export async function POST() {
  const user = await getVerifiedUser();
  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const admin = createAdminClient();
  const { error } = await admin.auth.admin.deleteUser(user.id);
  if (error) return Response.json({ error: "Could not delete the account" }, { status: 500 });

  return Response.json({ deleted: true });
}

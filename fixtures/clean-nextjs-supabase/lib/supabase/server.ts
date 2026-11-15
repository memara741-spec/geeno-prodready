import "server-only";
import { cookies } from "next/headers";
import { createServerClient } from "@supabase/ssr";
import { env } from "@/lib/env";

// A client that acts as the signed-in user. Row level security applies to everything it does.
export async function createClient() {
  const cookieStore = await cookies();
  return createServerClient(env().NEXT_PUBLIC_SUPABASE_URL, env().NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY, {
    cookies: {
      getAll: () => cookieStore.getAll(),
      setAll: (list) => {
        try {
          list.forEach(({ name, value, options }) => cookieStore.set(name, value, options));
        } catch (error) {
          // Called from a Server Component, where cookies are read-only. The session is refreshed on the next request.
          void error;
        }
      },
    },
  });
}

// Returns the verified user, or null. getUser() checks the token with the Auth server.
export async function getVerifiedUser() {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getUser();
  if (error || !data.user) return null;
  return data.user;
}

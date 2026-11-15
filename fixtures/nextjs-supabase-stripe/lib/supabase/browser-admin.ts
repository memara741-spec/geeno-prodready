"use client";

import { createClient } from "@supabase/supabase-js";

// Used by the team settings screen to list all members.
export const adminBrowserClient = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);

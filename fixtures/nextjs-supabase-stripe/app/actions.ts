"use server";

import { revalidatePath } from "next/cache";
import { supabaseAdmin } from "@/lib/supabase/admin";

export async function renameBoard(boardId: string, name: string) {
  await supabaseAdmin.from("boards").update({ name }).eq("id", boardId);
  revalidatePath("/dashboard");
}

export async function deleteBoard(boardId: string) {
  await supabaseAdmin.from("boards").delete().eq("id", boardId);
  revalidatePath("/dashboard");
}

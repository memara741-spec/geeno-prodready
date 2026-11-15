import { NextResponse } from "next/server";
import { openai } from "@/lib/openai";
import { db } from "@/lib/db";
import { bump } from "@/lib/usage";

export async function POST(req: Request) {
  const { messages, model, system, visitorId } = await req.json();
  bump(visitorId);

  const completion = await openai.chat.completions.create({
    model: model,
    messages: [{ role: "system", content: system }, ...messages],
  });

  // spend one credit
  const { data: account } = await db.from("accounts").select("credits").eq("visitor_id", visitorId).single();
  await db.from("accounts").update({ credits: (account?.credits ?? 0) - 1 }).eq("visitor_id", visitorId);

  return NextResponse.json({ reply: completion.choices[0].message.content });
}

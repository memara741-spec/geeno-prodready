import { NextResponse } from "next/server";
import { auth } from "@clerk/nextjs/server";
import { openai } from "@/lib/openai";
import { SYSTEM_PROMPT } from "@/lib/prompt";

export async function POST(req: Request) {
  const { userId } = await auth();
  if (!userId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { url } = await req.json();
  const page = await fetch(url);
  const html = await page.text();

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    max_tokens: 500,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: `Summarise this page:\n${html.slice(0, 20000)}` },
    ],
  });
  return NextResponse.json({ summary: completion.choices[0].message.content });
}

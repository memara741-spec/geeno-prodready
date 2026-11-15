import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

// GET /api/admin/purge?org=...  removes all completed tasks
export async function GET(req: Request) {
  const session = await getServerSession(authOptions);
  if ((session?.user as any)?.role !== "admin") return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const org = new URL(req.url).searchParams.get("org")!;
  await prisma.task.deleteMany({ where: { orgId: org, done: true } });
  return NextResponse.json({ ok: true });
}

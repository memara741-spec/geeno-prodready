import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { PrismaClient } from "@prisma/client";
import { authOptions } from "@/lib/auth";

export async function GET(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const prisma = new PrismaClient();
  const q = new URL(req.url).searchParams.get("q");
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM "Task" WHERE title ILIKE '%${q}%'`);
  return NextResponse.json(rows);
}

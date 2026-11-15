import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const users = await prisma.user.findMany({ where: { orgId: (session.user as any).orgId } });
  return NextResponse.json(users);
}

export async function PUT(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const user = await prisma.user.update({
    where: { id: (session.user as any).id },
    data: { email: body.email, role: body.role },
  });
  console.log("profile updated for", user.email);
  return NextResponse.json({ id: user.id });
}

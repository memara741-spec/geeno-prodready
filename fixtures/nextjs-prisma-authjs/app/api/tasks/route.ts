import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const tasks = await prisma.task.findMany();
  const result = [];
  for (const task of tasks) {
    const assignee = task.assigneeId ? await prisma.user.findUnique({ where: { id: task.assigneeId } }) : null;
    result.push({ ...task, assignee });
  }
  return NextResponse.json(result);
}

export async function POST(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  try {
    const task = await prisma.task.create({ data: { title: body.title, orgId: body.orgId } });
    return NextResponse.json(task);
  } catch (e) {}
  return NextResponse.json({ ok: false });
}

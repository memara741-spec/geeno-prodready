import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  const org = await prisma.organization.create({ data: { name: "Demo Org" } });
  await prisma.user.create({
    data: { email: "admin@teamtasks.app", passwordHash: await bcrypt.hash("admin123", 10), role: "admin", orgId: org.id },
  });
}

main();

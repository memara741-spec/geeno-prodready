"use client";

import { useEffect, useState } from "react";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export function AdminPanel() {
  const [count, setCount] = useState(0);
  useEffect(() => {
    prisma.user.count().then(setCount);
  }, []);
  return <p>{count} users</p>;
}

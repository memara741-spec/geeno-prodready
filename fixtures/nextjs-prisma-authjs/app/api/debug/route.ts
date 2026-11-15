import { NextResponse } from "next/server";

// temporary: check env on the server
export async function GET() {
  return NextResponse.json({ env: process.env, node: process.version });
}

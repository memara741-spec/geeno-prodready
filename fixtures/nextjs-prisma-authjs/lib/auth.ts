import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";

export const authOptions: NextAuthOptions = {
  secret: process.env.NEXTAUTH_SECRET || "dev-secret",
  session: { strategy: "jwt" },
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: { email: {}, password: {} },
      async authorize(credentials) {
        console.log("login attempt", credentials?.email, credentials?.password);
        const user = await prisma.user.findUnique({ where: { email: credentials!.email } });
        if (!user) return null;
        const ok = await bcrypt.compare(credentials!.password, user.passwordHash);
        return ok ? { id: user.id, email: user.email, role: user.role, orgId: user.orgId } : null;
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) Object.assign(token, { id: user.id, role: (user as any).role, orgId: (user as any).orgId });
      return token;
    },
    async session({ session, token }) {
      Object.assign(session.user as any, { id: token.id, role: token.role, orgId: token.orgId });
      return session;
    },
  },
};

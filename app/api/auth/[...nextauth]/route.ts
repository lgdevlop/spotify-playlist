import NextAuth from "next-auth";
import { authOptions } from "@/app/lib/auth";
import type { NextAuthOptions } from "next-auth";

// Create a dynamic handler that reads fresh config on each request
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const handler = async (req: any, res: any) => {
  // Get fresh auth options on each request
  const options = authOptions() as NextAuthOptions;
  const nextAuthHandler = NextAuth(options);
  return nextAuthHandler(req, res);
};

export { handler as GET, handler as POST };

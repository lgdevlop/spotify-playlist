import NextAuth from "next-auth";
import { authOptions } from "@/app/lib/auth";
import type { NextAuthOptions } from "next-auth";
import { getSpotifyConfig } from "@/app/lib/session-manager";

// Create a dynamic handler that reads fresh config on each request
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const handler = async (req: any, res: any) => {
  // Get credentials from session
  const credentials = await getSpotifyConfig();

  // Get fresh auth options on each request with session credentials
  const options = authOptions(credentials ? {
    clientId: credentials.clientId,
    clientSecret: credentials.clientSecret
  } : undefined) as NextAuthOptions;

  const nextAuthHandler = NextAuth(options);
  return nextAuthHandler(req, res);
};

export { handler as GET, handler as POST };

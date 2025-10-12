import "next-auth";

declare module "next-auth" {
  interface Session {
    accessToken?: string;
    // ✅ SECURITY FIX (SEC-002): Removed refreshToken from Session interface
    // Refresh tokens are kept server-side only in JWT tokens, never exposed to client
    spotifyId?: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
    refreshToken?: string;
    spotifyId?: string;
    expiresAt?: number;
  }
}

import NextAuth, { NextAuthOptions } from "next-auth";
import SpotifyProvider from "next-auth/providers/spotify";

export const authOptions: NextAuthOptions = {
  providers: [
    SpotifyProvider({
      clientId: process.env.SPOTIFY_CLIENT_ID!,
      clientSecret: process.env.SPOTIFY_CLIENT_SECRET!,
      authorization: {
        params: {
          scope:
            "user-read-email user-read-private user-top-read user-read-recently-played playlist-read-private playlist-read-collaborative playlist-modify-public playlist-modify-private",
        },
      },
    }),
  ],
  callbacks: {
    async jwt({ token, account, profile }) {
      if (account && profile) {
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;
        token.expiresAt = account.expires_at;
        token.spotifyId = (profile as { id: string }).id;
      }

      // Refresh the token if it's expired
      if (token.expiresAt && Date.now() / 1000 > token.expiresAt) {
        try {
          const response = await fetch("https://accounts.spotify.com/api/token", {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              grant_type: "refresh_token",
              refresh_token: token.refreshToken as string,
              client_id: process.env.SPOTIFY_CLIENT_ID!,
              client_secret: process.env.SPOTIFY_CLIENT_SECRET!,
            }),
          });

          const data = await response.json();

          if (response.ok) {
            token.accessToken = data.access_token;
            token.expiresAt = Math.floor(Date.now() / 1000) + data.expires_in;
            // Note: Spotify may return a new refresh_token, but we keep the old one if not provided
            if (data.refresh_token) {
              token.refreshToken = data.refresh_token;
            }
          } else {
            console.error("Failed to refresh token:", data);
          }
        } catch (error) {
          console.error("Error refreshing token:", error);
        }
      }

      return token;
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken;
      session.refreshToken = token.refreshToken;
      session.spotifyId = token.spotifyId;
      return session;
    },
  },
  pages: {
    signIn: "/auth/signin",
  },
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };

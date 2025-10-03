import SpotifyProvider from "next-auth/providers/spotify";
import type { SessionStrategy } from "next-auth";
import { logSecurityEvent, SecurityEventType } from "./security-logger";

// Store current credentials for token refresh
let currentCredentials: { clientId?: string; clientSecret?: string } = {};

export const authOptions = (credentials?: { clientId: string; clientSecret: string }) => {
  const clientId = credentials?.clientId || process.env.SPOTIFY_CLIENT_ID;
  const clientSecret = credentials?.clientSecret || process.env.SPOTIFY_CLIENT_SECRET;

  // Store credentials for token refresh
  currentCredentials = { clientId, clientSecret };

  const providers = [];
  if (clientId && clientSecret) {
    try {
      providers.push(
        SpotifyProvider({
          clientId,
          clientSecret,
          authorization: {
            params: {
              scope:
                "user-read-email user-read-private user-top-read user-read-recently-played playlist-read-private playlist-read-collaborative playlist-modify-public playlist-modify-private",
            },
          },
        })
      );
    } catch (error) {
      console.error("Error creating Spotify provider:", error);
    }
  }

  return {
    providers,
    debug: process.env.NODE_ENV === 'development',
    session: {
      strategy: "jwt" as SessionStrategy,
    },
    callbacks: {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      async jwt(params: any) {
        const { token, account, profile } = params;
        if (account && profile) {
          token.accessToken = account.access_token;
          token.refreshToken = account.refresh_token;
          token.expiresAt = account.expires_at;
          token.spotifyId = (profile as { id: string }).id;
        }

        // Refresh the token if it's expired
        if (token.expiresAt && Date.now() / 1000 > token.expiresAt) {
          try {
            // Use stored credentials for token refresh
            const response = await fetch("https://accounts.spotify.com/api/token", {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
              },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: token.refreshToken as string,
                client_id: currentCredentials.clientId!,
                client_secret: currentCredentials.clientSecret!,
              }),
            });

            const data = await response.json() as any;

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
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      async session(params: any) {
        const { session, token } = params;
        session.accessToken = token.accessToken;
        session.refreshToken = token.refreshToken;
        session.spotifyId = token.spotifyId;
        return session;
      },
    },
    pages: {
      signIn: "/auth/signin",
      error: "/auth/error",
    },
  };
};
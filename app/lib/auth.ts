import SpotifyProvider from "next-auth/providers/spotify";
import type { SessionStrategy, Account, Profile, Session } from "next-auth";
import type { JWT } from "next-auth/jwt";
import type { AuthConfig } from "../../types";
import { getSpotifyConfig } from "./session-manager";
import { logError } from './security-logger';

// ✅ SECURITY FIX (SEC-003): Removed global currentCredentials variable
// No more global state - using per-request credential retrieval

export const authOptions = (credentials?: AuthConfig) => {
  const clientId = credentials?.clientId || process.env.SPOTIFY_CLIENT_ID;
  const clientSecret = credentials?.clientSecret || process.env.SPOTIFY_CLIENT_SECRET;

  // ✅ SECURITY FIX (SEC-003): Removed global credential storage
  // Credentials are now retrieved per-request when needed

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
      logError("Error creating Spotify provider", error as Error);
    }
  }

  return {
    providers,
    debug: process.env.NODE_ENV === 'development',
    session: {
      strategy: "jwt" as SessionStrategy,
    },
    callbacks: {
      async jwt({ token, account, profile }: { token: JWT, account?: Account | null, profile?: Profile | null }) {
        // Initial token setup from OAuth callback
        if (account && profile) {
          token.accessToken = account.access_token;
          token.refreshToken = account.refresh_token;
          token.expiresAt = account.expires_at;
          token.spotifyId = (profile as { id: string }).id;
        }

        // ✅ SECURITY FIX (SEC-003): Per-request credential retrieval for token refresh
        // Refresh the token if it's expired
        if (token.expiresAt && Date.now() / 1000 > token.expiresAt) {
          try {
            // ✅ Get fresh credentials per request instead of using global variable
            const refreshConfig = await getSpotifyConfig();
            
            if (!refreshConfig?.clientId || !refreshConfig?.clientSecret) {
              logError("No credentials available for token refresh", "Missing client credentials");
              return token; // Return existing token instead of crashing
            }

            // ✅ SECURITY FIX (SEC-001): Preserved client secret encryption via getSpotifyConfig()
            const response = await fetch("https://accounts.spotify.com/api/token", {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
              },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: token.refreshToken as string,
                client_id: refreshConfig.clientId,
                client_secret: refreshConfig.clientSecret,
              }),
            });

            const data = await response.json() as {
              access_token: string;
              token_type: string;
              expires_in: number;
              refresh_token?: string;
              scope?: string;
            };

            if (response.ok) {
              token.accessToken = data.access_token;
              token.expiresAt = Math.floor(Date.now() / 1000) + data.expires_in;
              // Note: Spotify may return a new refresh_token, but we keep the old one if not provided
              if (data.refresh_token) {
                token.refreshToken = data.refresh_token;
              }
            } else {
              logError("Failed to refresh token", `Response: ${JSON.stringify(data)}`);
            }
          } catch (error) {
            logError("Error refreshing token", error as Error);
          }
        }

        return token;
      },
      // ✅ SECURITY FIX (SEC-002): Removed refreshToken from session callback
      // Refresh tokens are kept server-side only in JWT tokens, never exposed to client
      async session({ session, token }: { session: Session, token: JWT }) {
        session.accessToken = token.accessToken;
        // ❌ REMOVED: session.refreshToken = token.refreshToken; (SEC-002 fix)
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
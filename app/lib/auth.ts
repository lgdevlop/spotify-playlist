import SpotifyProvider from "next-auth/providers/spotify";
import type { SessionStrategy, Account, Profile, Session } from "next-auth";
import type { JWT } from "next-auth/jwt";
import type { AuthConfig } from "../../types";
import { logError, logJwtCallback } from './security-logger';
import { tokenStorage } from './token-storage';
import { tokenRefreshManager } from './token-refresh-manager';

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
        logJwtCallback('triggered', 'JWT callback triggered', {
          hasAccount: !!account,
          hasProfile: !!profile,
          hasAccessToken: !!token.accessToken,
          hasExpiresAt: !!token.expiresAt,
          spotifyId: token.spotifyId
        });

        // Initial token setup from OAuth callback
        if (account && profile) {
          logJwtCallback('initial_setup', 'Initial token setup from OAuth callback', {
            hasAccessToken: !!account.access_token,
            hasRefreshToken: !!account.refresh_token,
            expiresAt: account.expires_at,
            spotifyId: (profile as { id: string }).id
          });

          token.accessToken = account.access_token;
          token.spotifyId = (profile as { id: string }).id;
          token.expiresAt = account.expires_at;

          // ✅ SECURITY FIX (SEC-002): Store refresh token securely instead of in JWT
          if (account.refresh_token) {
            try {
              // Store refresh token in secure storage
              await tokenStorage.storeToken(
                (profile as { id: string }).id,
                account.refresh_token,
                account.expires_at || Math.floor(Date.now() / 1000) + 3600 // Default 1 hour if not provided
              );
              
              // Remove refresh token from JWT token
              token.refreshToken = undefined;
              
              logJwtCallback('initial_setup', 'Refresh token stored securely', {
                spotifyId: (profile as { id: string }).id,
                expiresAt: account.expires_at
              });
            } catch (error) {
              logError("Failed to store refresh token securely", error as Error);
              // Continue without storing refresh token - user will need to re-authenticate
            }
          }
        }

        // ✅ SECURITY FIX (SEC-002): Use TokenRefreshManager for automatic token refresh
        // Refresh the token if it's expired
        if (token.expiresAt && token.spotifyId && tokenRefreshManager.shouldRefreshToken(token.expiresAt)) {
          logJwtCallback('token_refresh', 'Token needs refresh', {
            spotifyId: token.spotifyId,
            expiresAt: token.expiresAt,
            currentTime: Math.floor(Date.now() / 1000)
          });

          try {
            // Use TokenRefreshManager for secure refresh
            const refreshResult = await tokenRefreshManager.refreshAccessToken(token.spotifyId);
            
            if (refreshResult.success) {
              token.accessToken = refreshResult.accessToken;
              token.expiresAt = refreshResult.expiresAt;
              
              logJwtCallback('token_refresh', 'Token refreshed successfully', {
                spotifyId: token.spotifyId,
                newExpiresAt: refreshResult.expiresAt,
                hasNewRefreshToken: !!refreshResult.refreshToken
              });
            } else {
              logJwtCallback('token_refresh', 'Token refresh failed', {
                spotifyId: token.spotifyId,
                error: refreshResult.error,
                rateLimited: refreshResult.rateLimited
              });
              
              // If refresh failed due to rate limiting, return existing token
              if (refreshResult.rateLimited) {
                return token;
              }
              
              // If refresh failed completely, clear the access token to force re-authentication
              token.accessToken = undefined;
            }
          } catch (error) {
            logJwtCallback('token_refresh', 'Error in token refresh', {
              spotifyId: token.spotifyId,
              errorType: error instanceof Error ? error.constructor.name : 'Unknown'
            });
            
            // Clear access token to force re-authentication
            token.accessToken = undefined;
          }
        }

        logJwtCallback('completed', 'JWT callback completed', {
          hasAccessToken: !!token.accessToken,
          spotifyId: token.spotifyId,
          expiresAt: token.expiresAt
        });

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
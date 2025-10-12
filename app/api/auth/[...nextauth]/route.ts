import NextAuth, { type NextAuthOptions } from "next-auth";
import SpotifyProvider from "next-auth/providers/spotify";
import type { SessionStrategy, Account, Profile, Session } from "next-auth";
import type { JWT } from "next-auth/jwt";
import { getSpotifyConfig } from "@/app/lib/session-manager";
import { logError, logAuthDebug, logJwtCallback, logCredentialsEvent, SecurityEventType } from '@/app/lib/security-logger';
import { cookies } from 'next/headers';

// ✅ SECURITY FIX (SEC-003): NO global credentials variable
// Using per-request credential retrieval for all operations

// ✅ Helper function to get credentials per request (no global state)
async function getCredentialsWithFallback() {
  try {
    const config = await getSpotifyConfig();
    if (config?.clientId && config?.clientSecret) {
      return config;
    }
  } catch (error) {
    logError("Error retrieving session credentials", error as Error);
  }
  
  return null;
}


// ✅ Create auth configuration that works with App Router
async function createAuthConfig(): Promise<NextAuthOptions> {
  const credentials = await getCredentialsWithFallback();

  if (credentials) {
    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
      "Using credentials from session manager in auth config",
      {
        source: 'auth_config_primary',
        hasClientId: !!credentials.clientId,
        hasClientSecret: !!credentials.clientSecret,
        hasRedirectUri: !!credentials.redirectUri
      }
    );
  } else {
    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
      "No credentials available in auth config",
      {
        source: 'auth_config_primary',
        hasCredentials: false
      }
    );
  }
  
  const providers = [];
  logAuthDebug('Creating auth config', undefined, {
    hasClientId: !!credentials?.clientId,
    hasClientSecret: !!credentials?.clientSecret,
    redirectUri: credentials?.redirectUri
  });
  if (credentials?.clientId && credentials?.clientSecret) {
    providers.push(
      SpotifyProvider({
        clientId: credentials.clientId,
        clientSecret: credentials.clientSecret,
        authorization: {
          params: {
            scope: "user-read-email user-read-private user-top-read user-read-recently-played playlist-read-private playlist-read-collaborative playlist-modify-public playlist-modify-private",
          },
        },
      })
    );
  }

  return {
    providers,
    debug: process.env.NODE_ENV === 'development',
    session: {
      strategy: "jwt" as SessionStrategy,
    },
    callbacks: {
      async jwt({ token, account, profile }: { token: JWT, account?: Account | null, profile?: Profile | null }) {
        // ✅ DEBUG: Track JWT callback execution
        logJwtCallback('triggered', 'JWT callback executed', {
          hasAccount: !!account,
          hasProfile: !!profile,
          hasAccessToken: !!token.accessToken,
          hasRefreshToken: !!token.refreshToken,
          expiresAt: token.expiresAt
        });

        // Initial token setup from OAuth callback
        if (account && profile) {
          logJwtCallback('initial_setup', 'Processing initial OAuth callback with account and profile');
          token.accessToken = account.access_token;
          token.refreshToken = account.refresh_token;
          token.expiresAt = account.expires_at;
          token.spotifyId = (profile as { id: string }).id;

          // SECURITY IMPROVEMENT: Do not save credentials in JWT
          // Credentials are available on the server via getSpotifyConfig()
          logJwtCallback('initial_setup', 'Initial token setup completed - no credentials in JWT');
          logJwtCallback('initial_setup', 'Initial token setup completed');
        }

        // SECURE VERSION - Use secure refresh endpoint
        if (token.expiresAt && Date.now() / 1000 > token.expiresAt) {
          try {
            logCredentialsEvent(
              SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
              "Attempting token refresh using secure refresh endpoint",
              {
                hasRefreshToken: !!token.refreshToken,
                tokenExpiresAt: token.expiresAt,
                currentTime: Math.floor(Date.now() / 1000),
                source: 'secure_refresh_endpoint'
              }
            );

            if (!token.refreshToken) {
              logCredentialsEvent(
                SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
                "No refresh token available for secure refresh",
                {
                  source: 'secure_refresh_endpoint'
                }
              );
              
              logError("No refresh token available", "Missing refresh token for token refresh");
              return token;
            }

            // Use secure refresh endpoint
            const response = await fetch(`${process.env.NEXTAUTH_URL || 'http://localhost:3000'}/api/spotify/secure-refresh`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({
                refreshToken: token.refreshToken
              }),
            });

            const data = await response.json() as {
              access_token: string;
              token_type: string;
              expires_in: number;
              refresh_token?: string;
              scope?: string;
              error?: string;
            };

            if (response.ok && data.access_token) {
              token.accessToken = data.access_token;
              token.expiresAt = Math.floor(Date.now() / 1000) + data.expires_in;
              if (data.refresh_token) {
                token.refreshToken = data.refresh_token;
              }

              logCredentialsEvent(
                SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
                "Successfully refreshed token using secure refresh endpoint",
                {
                  source: 'secure_refresh_endpoint',
                  newExpiresAt: token.expiresAt,
                  hasNewRefreshToken: !!data.refresh_token,
                  expiresIn: data.expires_in
                }
              );
            } else {
              logCredentialsEvent(
                SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
                "Failed to refresh token using secure refresh endpoint",
                {
                  source: 'secure_refresh_endpoint',
                  status: response.status,
                  error: JSON.stringify(data)
                }
              );
              
              logError("Failed to refresh token", `Status: ${response.status}, Response: ${JSON.stringify(data)}`);
            }
          } catch (error) {
            logCredentialsEvent(
              SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
              "Error during secure refresh endpoint call",
              {
                source: 'secure_refresh_endpoint',
                errorType: error instanceof Error ? error.constructor.name : 'Unknown'
              },
              undefined,
              error as Error
            );
            
            logError("Error refreshing token", error as Error);
          }
        }

        logJwtCallback('completed', 'JWT callback completed', {
          hasAccessToken: !!token.accessToken,
          hasRefreshToken: !!token.refreshToken,
          expiresAt: token.expiresAt,
          spotifyId: token.spotifyId
        });
        return token;
      },
      // ✅ SECURITY FIX (SEC-002): Removed refreshToken from session callback
      // DO NOT add credentials here! (exposes to client)
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
    // Add for dev: relax cookies to avoid host issues
    useSecureCookies: process.env.NODE_ENV === 'production',
    cookies: {
      sessionToken: {
        name: process.env.NODE_ENV === 'production'
          ? '__Secure-next-auth.session-token'
          : 'next-auth.session-token',  // Remove __Secure- prefix in dev
        options: {
          httpOnly: true,
          sameSite: 'lax',
          path: '/',
          secure: process.env.NODE_ENV === 'production',
        },
      },
    },
  };
}

// ✅ App Router Pattern: Create the NextAuth handler
const handler = async (req: Request, context: { params: Promise<{ nextauth: string[] }> }) => {
  logAuthDebug('NextAuth handler called', undefined, {
    url: req.url,
    host: req.headers.get('host'),
    method: req.method
  });
  
  const cookieStore = await cookies();
  const spotifySession = cookieStore.get('spotify-session')?.value;
  
  logAuthDebug('Session cookies check', undefined, {
    hasSpotifySession: !!spotifySession
  });
  
  const config = await createAuthConfig();
  
  logAuthDebug('Auth config created', undefined, {
    providersCount: config.providers.length,
    hasProviders: config.providers.length > 0
  });
  
  const nextAuthHandler = NextAuth(config);
  return nextAuthHandler(req, context);
};

export { handler as GET, handler as POST };
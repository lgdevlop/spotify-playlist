import SpotifyProvider from "next-auth/providers/spotify";
import fs from "fs";
import path from "path";
import type { SessionStrategy } from "next-auth";

const configFilePath = path.join(process.cwd(), "spotify-config.json");

function getSpotifyCredentials() {
  let clientId = process.env.SPOTIFY_CLIENT_ID;
  let clientSecret = process.env.SPOTIFY_CLIENT_SECRET;

  // Always check config file to get the latest values
  // This ensures dynamic updates are reflected immediately
  try {
    if (fs.existsSync(configFilePath)) {
      const config = JSON.parse(fs.readFileSync(configFilePath, "utf-8"));
      // Use config file values if they exist, otherwise fall back to env vars
      clientId = config.clientId || clientId;
      clientSecret = config.clientSecret || clientSecret;
    }
  } catch (error) {
    console.error("Error reading config file:", error);
  }

  console.log('getSpotifyCredentials - clientId:', clientId ? 'defined' : 'undefined');
  console.log('getSpotifyCredentials - clientSecret:', clientSecret ? 'defined' : 'undefined');

  return { clientId, clientSecret };
}

export const authOptions = () => {
  const { clientId, clientSecret } = getSpotifyCredentials();

  console.log('authOptions clientId:', clientId)
  console.log('authOptions clientSecret:', clientSecret)

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
            // Get fresh credentials for token refresh
            const freshCredentials = getSpotifyCredentials();
            const response = await fetch("https://accounts.spotify.com/api/token", {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
              },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: token.refreshToken as string,
                client_id: freshCredentials.clientId!,
                client_secret: freshCredentials.clientSecret!,
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
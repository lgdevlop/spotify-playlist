import { getSpotifyConfig } from './session-manager';

export interface SpotifyTokens {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export class TokenManager {
  static async exchangeCodeForTokens(code: string, redirectUri: string): Promise<SpotifyTokens> {
    const credentials = await getSpotifyConfig();
    if (!credentials) throw new Error("No credentials configured");
    
    const response = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: {
        "Authorization": `Basic ${Buffer.from(`${credentials.clientId}:${credentials.clientSecret}`).toString('base64')}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri
      })
    });
    
    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.statusText}`);
    }
    
    return response.json() as Promise<SpotifyTokens>;
  }
  
  static async refreshToken(refreshToken: string): Promise<SpotifyTokens> {
    const credentials = await getSpotifyConfig();
    if (!credentials) throw new Error("No credentials configured");
    
    const response = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: {
        "Authorization": `Basic ${Buffer.from(`${credentials.clientId}:${credentials.clientSecret}`).toString('base64')}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken
      })
    });
    
    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.statusText}`);
    }
    
    return response.json() as Promise<SpotifyTokens>;
  }
}
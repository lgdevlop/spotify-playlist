import { getSpotifyConfig } from './session-manager';
import { logCredentialsEvent, SecurityEventType } from './security-logger';

export interface SpotifyTokens {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export class TokenManager {
  static async exchangeCodeForTokens(code: string, redirectUri: string): Promise<SpotifyTokens> {
    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
      "Attempting token exchange using session credentials",
      {
        source: 'token_manager_exchange',
        hasRedirectUri: !!redirectUri
      }
    );

    const credentials = await getSpotifyConfig();
    if (!credentials) {
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
        "No credentials available for token exchange",
        {
          source: 'token_manager_exchange'
        }
      );
      throw new Error("No credentials configured");
    }

    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
      "Using credentials for token exchange",
      {
        source: 'token_manager_exchange',
        hasClientId: !!credentials.clientId,
        hasClientSecret: !!credentials.clientSecret
      }
    );
    
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
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
        "Token exchange failed",
        {
          source: 'token_manager_exchange',
          status: response.status,
          statusText: response.statusText
        }
      );
      throw new Error(`Token exchange failed: ${response.statusText}`);
    }

    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
      "Token exchange completed successfully",
      {
        source: 'token_manager_exchange',
        status: response.status
      }
    );
    
    return response.json() as Promise<SpotifyTokens>;
  }
  
  static async refreshToken(refreshToken: string): Promise<SpotifyTokens> {
    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
      "Attempting token refresh using session credentials",
      {
        source: 'token_manager_refresh',
        hasRefreshToken: !!refreshToken
      }
    );

    const credentials = await getSpotifyConfig();
    if (!credentials) {
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
        "No credentials available for token refresh",
        {
          source: 'token_manager_refresh'
        }
      );
      throw new Error("No credentials configured");
    }

    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
      "Using credentials for token refresh",
      {
        source: 'token_manager_refresh',
        hasClientId: !!credentials.clientId,
        hasClientSecret: !!credentials.clientSecret
      }
    );
    
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
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
        "Token refresh failed",
        {
          source: 'token_manager_refresh',
          status: response.status,
          statusText: response.statusText
        }
      );
      throw new Error(`Token refresh failed: ${response.statusText}`);
    }

    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
      "Token refresh completed successfully",
      {
        source: 'token_manager_refresh',
        status: response.status
      }
    );
    
    return response.json() as Promise<SpotifyTokens>;
  }
}
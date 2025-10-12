import { NextResponse } from 'next/server';
import { getSpotifyConfig } from '@/app/lib/session-manager';
import { logCredentialsEvent, SecurityEventType } from '@/app/lib/security-logger';

export async function POST(request: Request) {
  try {
    const { refreshToken } = await request.json();
    
    if (!refreshToken) {
      return NextResponse.json(
        { error: "Refresh token is required" },
        { status: 400 }
      );
    }

    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
      "Secure refresh endpoint called",
      {
        hasRefreshToken: !!refreshToken,
        source: 'secure_refresh_endpoint'
      }
    );

    // Always use server-side credentials
    const credentials = await getSpotifyConfig();
    
    if (!credentials?.clientId || !credentials?.clientSecret) {
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
        "No server credentials available in secure refresh",
        {
          hasClientId: !!credentials?.clientId,
          hasClientSecret: !!credentials?.clientSecret
        }
      );
      
      return NextResponse.json(
        { error: "No Spotify credentials configured" },
        { status: 400 }
      );
    }

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

    const data = await response.json();

    if (response.ok) {
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        "Secure refresh completed successfully",
        {
          source: 'secure_refresh_endpoint',
          expiresIn: data.expires_in
        }
      );
      
      return NextResponse.json(data);
    } else {
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
        "Secure refresh failed",
        {
          source: 'secure_refresh_endpoint',
          status: response.status,
          error: JSON.stringify(data)
        }
      );
      
      return NextResponse.json(
        { error: "Failed to refresh token" },
        { status: response.status }
      );
    }
  } catch (error) {
    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
      "Error in secure refresh endpoint",
      {
        source: 'secure_refresh_endpoint',
        errorType: error instanceof Error ? error.constructor.name : 'Unknown'
      },
      undefined,
      error as Error
    );
    
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
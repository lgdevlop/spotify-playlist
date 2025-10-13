import { NextRequest, NextResponse } from 'next/server';
import { getSpotifyConfig } from '@/app/lib/session-manager';
import { tokenRefreshManager } from '@/app/lib/token-refresh-manager';
import { logCredentialsEvent, SecurityEventType } from '@/app/lib/security-logger';

export async function POST(request: NextRequest) {
  try {
    const { refreshToken, userId } = await request.json();
    
    // ✅ SECURITY FIX (SEC-002): Prefer userId-based refresh over direct refresh token
    if (userId) {
      logCredentialsEvent(
        SecurityEventType.SEC_002_REFRESH_ATTEMPT,
        "Token refresh request using userId",
        {
          userId,
          source: 'refresh_endpoint',
          hasRefreshToken: !!refreshToken
        }
      );

      // Extract client IP for rate limiting
      const clientIP = request.headers.get('x-forwarded-for') ||
                      request.headers.get('x-real-ip') ||
                      'unknown';

      // Use TokenRefreshManager for secure refresh
      const refreshResult = await tokenRefreshManager.refreshAccessToken(userId, clientIP);
      
      if (refreshResult.success) {
        logCredentialsEvent(
          SecurityEventType.SEC_002_REFRESH_SUCCESS,
          "Token refreshed successfully via TokenRefreshManager",
          {
            userId,
            source: 'refresh_endpoint',
            hasNewRefreshToken: !!refreshResult.refreshToken
          }
        );

        return NextResponse.json({
          access_token: refreshResult.accessToken,
          expires_in: refreshResult.expiresAt ? Math.floor(refreshResult.expiresAt - Date.now() / 1000) : undefined,
          refresh_token: refreshResult.refreshToken
        });
      } else {
        const statusCode = refreshResult.rateLimited ? 429 : 400;
        
        logCredentialsEvent(
          SecurityEventType.SEC_002_REFRESH_FAILURE,
          "Token refresh failed via TokenRefreshManager",
          {
            userId,
            source: 'refresh_endpoint',
            error: refreshResult.error,
            rateLimited: refreshResult.rateLimited
          }
        );

        return NextResponse.json(
          {
            error: refreshResult.error,
            rateLimited: refreshResult.rateLimited
          },
          { status: statusCode }
        );
      }
    }

    // Legacy fallback: direct refresh token usage (deprecated)
    if (refreshToken) {
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        "Legacy token refresh request using direct refresh token",
        {
          source: 'refresh_endpoint_legacy',
          hasRefreshToken: !!refreshToken
        }
      );

      // Get stored credentials from session (not from client)
      const credentials = await getSpotifyConfig();
      if (!credentials) {
        return NextResponse.json({ error: "No credentials configured" }, { status: 400 });
      }
      
      // Use server-side credentials for refresh
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
          "Legacy token refresh failed",
          {
            source: 'refresh_endpoint_legacy',
            status: response.status,
            statusText: response.statusText
          }
        );
        return NextResponse.json({ error: "Token refresh failed" }, { status: response.status });
      }
      
      const tokens = await response.json();
      
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        "Legacy token refresh completed",
        {
          source: 'refresh_endpoint_legacy',
          hasAccessToken: !!tokens.access_token,
          expiresIn: tokens.expires_in
        }
      );

      return NextResponse.json(tokens);
    }
    
    return NextResponse.json({ error: "Either userId or refreshToken is required" }, { status: 400 });
  } catch (error) {
    logCredentialsEvent(
      SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
      "Error in token refresh endpoint",
      {
        source: 'refresh_endpoint',
        errorType: error instanceof Error ? error.constructor.name : 'Unknown'
      },
      undefined,
      error as Error
    );
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
import { NextResponse } from 'next/server';
import { getSpotifyConfig } from '@/app/lib/session-manager';
import { tokenRefreshManager } from '@/app/lib/token-refresh-manager';
import { logCredentialsEvent, SecurityEventType } from '@/app/lib/security-logger';

export async function POST(request: Request) {
  try {
    const { refreshToken, userId } = await request.json();
    
    // ✅ SECURITY FIX (SEC-002): Prefer userId-based refresh over direct refresh token
    if (userId) {
      logCredentialsEvent(
        SecurityEventType.SEC_002_REFRESH_ATTEMPT,
        "Secure refresh endpoint called using userId",
        {
          userId,
          source: 'secure_refresh_endpoint',
          hasRefreshToken: !!refreshToken
        }
      );

      // Extract client IP for rate limiting
      const headers = request.headers as Headers;
      const clientIP = headers.get('x-forwarded-for') ||
                      headers.get('x-real-ip') ||
                      'unknown';

      // Use TokenRefreshManager for secure refresh
      const refreshResult = await tokenRefreshManager.refreshAccessToken(userId, clientIP);
      
      if (refreshResult.success) {
        logCredentialsEvent(
          SecurityEventType.SEC_002_REFRESH_SUCCESS,
          "Secure refresh completed successfully via TokenRefreshManager",
          {
            userId,
            source: 'secure_refresh_endpoint',
            hasNewRefreshToken: !!refreshResult.refreshToken,
            expiresIn: refreshResult.expiresAt ? Math.floor(refreshResult.expiresAt - Date.now() / 1000) : undefined
          }
        );

        return NextResponse.json({
          access_token: refreshResult.accessToken,
          token_type: "Bearer",
          expires_in: refreshResult.expiresAt ? Math.floor(refreshResult.expiresAt - Date.now() / 1000) : undefined,
          refresh_token: refreshResult.refreshToken
        });
      } else {
        // Determine status code based on error type
        let statusCode = 400;
        if (refreshResult.rateLimited) {
          statusCode = 429;
        } else if (refreshResult.error?.includes('Network') ||
                   refreshResult.error?.includes('ECONNREFUSED') ||
                   refreshResult.error?.includes('ENOTFOUND') ||
                   refreshResult.error?.includes('ETIMEDOUT') ||
                   refreshResult.error?.includes('unreachable')) {
          statusCode = 500;
        }
        
        logCredentialsEvent(
          SecurityEventType.SEC_002_REFRESH_FAILURE,
          "Secure refresh failed via TokenRefreshManager",
          {
            userId,
            source: 'secure_refresh_endpoint',
            error: refreshResult.error,
            rateLimited: refreshResult.rateLimited,
            statusCode
          }
        );

        const response: Record<string, unknown> = {
          error: statusCode === 500 ? "Internal server error" : refreshResult.error
        };

        if (refreshResult.rateLimited) {
          response.rateLimited = true;
          return NextResponse.json(response, {
            status: statusCode,
            headers: {
              'Retry-After': '60',
              'X-RateLimit-Limit': '5',
              'X-RateLimit-Remaining': '0',
              'X-RateLimit-Reset': Math.ceil(Date.now() / 1000 + 60).toString()
            }
          });
        }

        return NextResponse.json(response, { status: statusCode });
      }
    }

    // Legacy fallback: direct refresh token usage (deprecated for security)
    if (refreshToken) {
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        "Legacy secure refresh endpoint called using direct refresh token",
        {
          source: 'secure_refresh_endpoint_legacy',
          hasRefreshToken: !!refreshToken
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
          "Legacy secure refresh completed successfully",
          {
            source: 'secure_refresh_endpoint_legacy',
            expiresIn: data.expires_in
          }
        );
        
        return NextResponse.json(data);
      } else {
        logCredentialsEvent(
          SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
          "Legacy secure refresh failed",
          {
            source: 'secure_refresh_endpoint_legacy',
            status: response.status,
            error: JSON.stringify(data)
          }
        );
        
        return NextResponse.json(
          { error: "Failed to refresh token" },
          { status: response.status }
        );
      }
    }

    return NextResponse.json(
      { error: "Either userId or refreshToken is required" },
      { status: 400 }
    );
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
import { tokenRefreshManager } from './token-refresh-manager';
import { logCredentialsEvent, SecurityEventType } from './security-logger';

export class SpotifyProxy {
  /**
   * Makes an authenticated request to Spotify API with automatic token refresh
   */
  static async makeAuthenticatedRequest(
    endpoint: string,
    accessToken: string,
    userId?: string,
    maxRetries = 1
  ): Promise<unknown> {
    try {
      const response = await fetch(`https://api.spotify.com/v1${endpoint}`, {
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        }
      });
      
      if (response.ok) {
        return response.json();
      }
      
      // Handle token expiration (401) with automatic refresh
      if (response.status === 401 && userId && maxRetries > 0) {
        logCredentialsEvent(
          SecurityEventType.SEC_002_REFRESH_ATTEMPT,
          "Token expired during API call, attempting refresh",
          {
            userId,
            source: 'spotify_proxy',
            endpoint,
            remainingRetries: maxRetries - 1
          }
        );

        try {
          const refreshResult = await tokenRefreshManager.refreshAccessToken(userId);
          
          if (refreshResult.success && refreshResult.accessToken) {
            logCredentialsEvent(
              SecurityEventType.SEC_002_REFRESH_SUCCESS,
              "Token refreshed successfully, retrying API call",
              {
                userId,
                source: 'spotify_proxy',
                endpoint
              }
            );

            // Retry the request with new token
            return this.makeAuthenticatedRequest(
              endpoint,
              refreshResult.accessToken,
              userId,
              maxRetries - 1
            );
          } else {
            logCredentialsEvent(
              SecurityEventType.SEC_002_REFRESH_FAILURE,
              "Failed to refresh token for API call",
              {
                userId,
                source: 'spotify_proxy',
                endpoint,
                error: refreshResult.error
              }
            );
          }
        } catch (error) {
          logCredentialsEvent(
            SecurityEventType.SEC_002_REFRESH_FAILURE,
            "Error during token refresh for API call",
            {
              userId,
              source: 'spotify_proxy',
              endpoint,
              errorType: error instanceof Error ? error.constructor.name : 'Unknown'
            },
            undefined,
            error as Error
          );
        }
      }
      
      // If we get here, the request failed and we couldn't refresh
      const errorText = await response.text();
      throw new Error(`Spotify API error: ${response.status} ${response.statusText} - ${errorText}`);
    } catch (error) {
      // Re-throw the error with additional context
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`Unexpected error in Spotify API call: ${error}`);
    }
  }
  
  /**
   * Gets user's top tracks with automatic token refresh
   */
  static async getTopTracks(
    accessToken: string,
    timeRange?: string,
    limit?: number,
    userId?: string
  ) {
    return this.makeAuthenticatedRequest(
      `/me/top/tracks?time_range=${timeRange || 'short_term'}&limit=${limit || 5}`,
      accessToken,
      userId
    );
  }
  
  /**
   * Gets user's playlists with automatic token refresh
   */
  static async getPlaylists(
    accessToken: string,
    limit?: number,
    userId?: string
  ) {
    return this.makeAuthenticatedRequest(
      `/me/playlists?limit=${limit || 5}`,
      accessToken,
      userId
    );
  }
}
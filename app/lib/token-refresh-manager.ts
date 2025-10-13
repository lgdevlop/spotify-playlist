import { tokenStorage } from './token-storage';
import { getSpotifyConfig } from './session-manager';
import { logCredentialsEvent, SecurityEventType } from './security-logger';
import type { SpotifyTokens } from './token-manager';

/**
 * Interface for rate limiting control
 */
interface RateLimitEntry {
  count: number;
  resetTime: number;
  lastAttempt: number;
}

/**
 * Result of the refresh operation
 */
export interface RefreshResult {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: number;
  error?: string;
  rateLimited?: boolean;
}

/**
 * Automatic token refresh manager with rate limiting
 * This class manages automatic refresh of access tokens using securely stored
 * refresh tokens, with rate limiting to prevent abuse
 */
export class TokenRefreshManager {
  private static instance: TokenRefreshManager;
  private readonly RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute in milliseconds
  private readonly RATE_LIMIT_MAX_REQUESTS = 5; // Maximum 5 requests per minute per user
  private readonly RETRY_DELAY = 1000; // 1 second between retries
  private readonly MAX_RETRIES = 3; // Maximum 3 retry attempts
  private readonly TEST_RETRY_DELAY = 1; // 1ms between retries in test environment
  
  // Rate limiting by user
  private rateLimitMap = new Map<string, RateLimitEntry>();
  
  // Rate limiting by IP (additional)
  private ipRateLimitMap = new Map<string, RateLimitEntry>();

  private constructor() {}

  /**
   * Gets singleton instance of TokenRefreshManager
   */
  static getInstance(): TokenRefreshManager {
    if (!TokenRefreshManager.instance) {
      TokenRefreshManager.instance = new TokenRefreshManager();
    }
    return TokenRefreshManager.instance;
  }

  /**
   * Checks if user has exceeded rate limit
   */
  private checkRateLimit(userId: string, ipAddress?: string): { allowed: boolean; resetTime?: number } {
    const now = Date.now();
    
    // Check rate limit by user
    const userLimit = this.rateLimitMap.get(userId);
    if (userLimit) {
      // If time window has expired, reset counter
      if (now > userLimit.resetTime) {
        this.rateLimitMap.set(userId, {
          count: 1,
          resetTime: now + this.RATE_LIMIT_WINDOW,
          lastAttempt: now
        });
      } else {
        // Check if limit was exceeded
        if (userLimit.count >= this.RATE_LIMIT_MAX_REQUESTS) {
          logCredentialsEvent(
            SecurityEventType.SEC_002_RATE_LIMIT_EXCEEDED,
            "User rate limit exceeded",
            {
              userId,
              source: 'token_refresh_manager',
              count: userLimit.count,
              maxRequests: this.RATE_LIMIT_MAX_REQUESTS,
              resetTime: new Date(userLimit.resetTime).toISOString()
            }
          );
          return { allowed: false, resetTime: userLimit.resetTime };
        }
        
        // Increment counter
        userLimit.count++;
        userLimit.lastAttempt = now;
      }
    } else {
      // First user request
      this.rateLimitMap.set(userId, {
        count: 1,
        resetTime: now + this.RATE_LIMIT_WINDOW,
        lastAttempt: now
      });
    }

    // Check rate limit by IP (additional)
    if (ipAddress) {
      const ipLimit = this.ipRateLimitMap.get(ipAddress);
      if (ipLimit) {
        if (now > ipLimit.resetTime) {
          this.ipRateLimitMap.set(ipAddress, {
            count: 1,
            resetTime: now + this.RATE_LIMIT_WINDOW,
            lastAttempt: now
          });
        } else if (ipLimit.count >= this.RATE_LIMIT_MAX_REQUESTS * 2) { // Higher limit per IP
          logCredentialsEvent(
            SecurityEventType.SEC_002_RATE_LIMIT_EXCEEDED,
            "IP rate limit exceeded",
            {
              userId,
              ipAddress,
              source: 'token_refresh_manager',
              count: ipLimit.count,
              maxRequests: this.RATE_LIMIT_MAX_REQUESTS * 2,
              resetTime: new Date(ipLimit.resetTime).toISOString()
            }
          );
          return { allowed: false, resetTime: ipLimit.resetTime };
        } else {
          ipLimit.count++;
          ipLimit.lastAttempt = now;
        }
      } else {
        this.ipRateLimitMap.set(ipAddress, {
          count: 1,
          resetTime: now + this.RATE_LIMIT_WINDOW,
          lastAttempt: now
        });
      }
    }

    return { allowed: true };
  }

  /**
   * Clears expired rate limiting entries
   */
  private cleanupRateLimits(): void {
    const now = Date.now();
    
    // Clear rate limits by user
    for (const [userId, entry] of this.rateLimitMap.entries()) {
      if (now > entry.resetTime) {
        this.rateLimitMap.delete(userId);
      }
    }
    
    // Clear rate limits by IP
    for (const [ip, entry] of this.ipRateLimitMap.entries()) {
      if (now > entry.resetTime) {
        this.ipRateLimitMap.delete(ip);
      }
    }
  }

  /**
   * Checks if running in test environment
   */
  private isTestEnvironment(): boolean {
    return process.env.NODE_ENV === 'test' ||
           process.env.BUN_ENV === 'test' ||
           process.env.JEST_WORKER_ID !== undefined ||
           process.env.VITEST_WORKER_ID !== undefined;
  }

  /**
   * Waits for a period before retry (exponential backoff)
   */
  private async delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Determines if an error should be retried based on status and error data
   */
  private shouldRetryError(status: number, errorData: { error?: string } | undefined): boolean {
    // Errors that should NOT be retried (permanent errors)
    if (status === 400) {
      const error = errorData?.error || '';
      if (error === 'invalid_grant' || error === 'invalid_request' || error === 'invalid_client') {
        return false;
      }
    }
    
    if (status === 401) {
      const error = errorData?.error || '';
      if (error === 'invalid_token') {
        return false;
      }
    }
    
    if (status === 403) {
      const error = errorData?.error || '';
      if (error === 'insufficient_scope') {
        return false;
      }
    }
    
    // Errors that CAN be retried (temporary errors)
    if (status >= 500 && status < 600) {
      // Server errors (5xx)
      return true;
    }
    
    if (status === 503) {
      const error = errorData?.error || '';
      if (error === 'temporarily_unavailable') {
        return true;
      }
    }
    
    if (status === 429) {
      // Rate limiting - can be retried after waiting
      return true;
    }
    
    // For other HTTP statuses, do not retry
    if (status > 0) {
      return false;
    }
    
    // For network errors (no HTTP status), allow retry
    return true;
  }

  /**
   * Performs token refresh with automatic retry
   */
  private async performTokenRefresh(refreshToken: string): Promise<SpotifyTokens> {
    const credentials = await getSpotifyConfig();
    if (!credentials?.clientId || !credentials?.clientSecret) {
      throw new Error("No Spotify credentials configured");
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

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const enhancedError = new Error(`Token refresh failed: ${response.status} ${response.statusText} - ${JSON.stringify(errorData)}`) as Error & { status: number; errorData: { error?: string } };
      enhancedError.status = response.status;
      enhancedError.errorData = errorData;
      throw enhancedError;
    }

    return response.json() as Promise<SpotifyTokens>;
  }

  /**
   * Refreshes an access token using the stored refresh token
   */
  async refreshAccessToken(
    userId: string, 
    ipAddress?: string,
    retryCount = 0
  ): Promise<RefreshResult> {
    try {
      logCredentialsEvent(
        SecurityEventType.SEC_002_REFRESH_ATTEMPT,
        "Attempting to refresh access token",
        {
          userId,
          source: 'token_refresh_manager',
          retryCount,
          ipAddress: ipAddress ? '[REDACTED]' : undefined
        }
      );

      // Check rate limiting
      const rateLimitCheck = this.checkRateLimit(userId, ipAddress);
      if (!rateLimitCheck.allowed) {
        return {
          success: false,
          error: `Rate limit exceeded. Try again after ${new Date(rateLimitCheck.resetTime!).toLocaleTimeString()}`,
          rateLimited: true
        };
      }

      // Get refresh token from secure storage
      const refreshToken = await tokenStorage.getToken(userId);
      if (!refreshToken) {
        logCredentialsEvent(
          SecurityEventType.SEC_002_REFRESH_FAILURE,
          "No refresh token found for user",
          {
            userId,
            source: 'token_refresh_manager'
          }
        );
        return {
          success: false,
          error: "No refresh token available"
        };
      }

      // Attempt to refresh
      const tokens = await this.performTokenRefresh(refreshToken);
      
      // Calculate expiration time
      const expiresAt = Math.floor(Date.now() / 1000) + tokens.expires_in;

      // If a new refresh token was returned, store it
      if (tokens.refresh_token) {
        await tokenStorage.storeToken(userId, tokens.refresh_token, expiresAt);
      }

      logCredentialsEvent(
        SecurityEventType.SEC_002_REFRESH_SUCCESS,
        "Token refreshed successfully",
        {
          userId,
          source: 'token_refresh_manager',
          expiresIn: tokens.expires_in,
          hasNewRefreshToken: !!tokens.refresh_token,
          retryCount,
          accessToken: tokens.access_token // This will be sanitized to [REDACTED]
        }
      );

      return {
        success: true,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const status = (error as Error & { status?: number }).status || 0;
      const errorData = (error as Error & { errorData?: { error?: string } }).errorData || {};
      
      logCredentialsEvent(
        SecurityEventType.SEC_002_REFRESH_FAILURE,
        "Token refresh failed",
        {
          userId,
          source: 'token_refresh_manager',
          errorType: error instanceof Error ? error.constructor.name : 'Unknown',
          retryCount,
          status,
          errorCode: errorData?.error || 'unknown'
        },
        undefined,
        error instanceof Error ? error : new Error(errorMessage)
      );

      // Check if error should be retried using the new classification logic
      const shouldRetry = this.shouldRetryError(status, errorData);
      
      if (shouldRetry && retryCount < this.MAX_RETRIES) {
        // Use reduced delay in test environment to avoid timeouts
        const baseDelay = this.isTestEnvironment() ? this.TEST_RETRY_DELAY : this.RETRY_DELAY;
        const delayMs = baseDelay * Math.pow(2, retryCount);
        
        logCredentialsEvent(
          SecurityEventType.SEC_002_REFRESH_ATTEMPT,
          `Retrying token refresh after ${delayMs}ms (error classified as retryable)`,
          {
            userId,
            source: 'token_refresh_manager',
            retryCount: retryCount + 1,
            delayMs,
            status,
            errorCode: errorData?.error || 'unknown',
            isTestEnvironment: this.isTestEnvironment()
          }
        );

        await this.delay(delayMs);
        return this.refreshAccessToken(userId, ipAddress, retryCount + 1);
      }

      logCredentialsEvent(
        SecurityEventType.SEC_002_REFRESH_FAILURE,
        `Token refresh failed permanently (error not retryable or max retries exceeded)`,
        {
          userId,
          source: 'token_refresh_manager',
          retryCount,
          status,
          errorCode: errorData?.error || 'unknown',
          shouldRetry,
          maxRetries: this.MAX_RETRIES
        }
      );

      return {
        success: false,
        error: errorMessage
      };
    }
  }

  /**
   * Checks if a token needs to be refreshed
   */
  shouldRefreshToken(expiresAt: number, bufferSeconds = 300): boolean {
    // Refresh 5 minutes before expiration
    return Date.now() / 1000 > (expiresAt - bufferSeconds);
  }

  /**
   * Gets rate limiting statistics
   */
  getRateLimitStats(): {
    totalUsers: number;
    totalIPs: number;
    activeUsers: number;
    activeIPs: number;
  } {
    const now = Date.now();
    let activeUsers = 0;
    let activeIPs = 0;

    for (const entry of this.rateLimitMap.values()) {
      if (now <= entry.resetTime) {
        activeUsers++;
      }
    }

    for (const entry of this.ipRateLimitMap.values()) {
      if (now <= entry.resetTime) {
        activeIPs++;
      }
    }

    return {
      totalUsers: this.rateLimitMap.size,
      totalIPs: this.ipRateLimitMap.size,
      activeUsers,
      activeIPs
    };
  }

  /**
   * Clears all rate limiting entries (for testing)
   */
  clearRateLimits(): void {
    this.rateLimitMap.clear();
    this.ipRateLimitMap.clear();
    
    logCredentialsEvent(
      SecurityEventType.AUTH_DEBUG,
      "Cleared all rate limit entries",
      {
        source: 'token_refresh_manager'
      }
    );
  }

  /**
   * Performs periodic cleanup
   */
  cleanup(): void {
    this.cleanupRateLimits();
    tokenStorage.cleanup();
  }
}

// Export singleton instance
export const tokenRefreshManager = TokenRefreshManager.getInstance();
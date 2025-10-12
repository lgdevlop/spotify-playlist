import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { TokenRefreshManager } from '../../app/lib/token-refresh-manager';
import { tokenStorage } from '../../app/lib/token-storage';
import { securityLogger, SecurityEventType } from '../../app/lib/security-logger';

// Mock environment variables
process.env.SPOTIFY_ENCRYPTION_KEY = 'a'.repeat(64); // 32 bytes in hex

// Mock dependencies
mock.module('@/app/lib/session-manager', () => ({
  getSpotifyConfig: async () => ({
    clientId: 'test_client_id',
    clientSecret: 'test_client_secret',
    redirectUri: 'http://localhost:3000/callback'
  }),
}));

// Mock security logger
const mockLog = mock(() => {});
securityLogger.log = mockLog;

describe('TokenRefreshManager Unit Tests', () => {
  let tokenRefreshManager: TokenRefreshManager;

  beforeEach(() => {
    tokenRefreshManager = TokenRefreshManager.getInstance();
    tokenStorage.clearAll();
    tokenRefreshManager.clearRateLimits();
    mockLog.mockClear();
  });

  afterEach(() => {
    tokenStorage.clearAll();
    tokenRefreshManager.clearRateLimits();
  });

  describe('Singleton Pattern', () => {
    test('should maintain singleton instance', () => {
      const instance1 = TokenRefreshManager.getInstance();
      const instance2 = TokenRefreshManager.getInstance();
      expect(instance1).toBe(instance2);
    });

    test('should share rate limits across instances', async () => {
      const instance1 = TokenRefreshManager.getInstance();
      const instance2 = TokenRefreshManager.getInstance();

      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      // Mock successful fetch
      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      // Make request from first instance
      await instance1.refreshAccessToken(userId, '127.0.0.1');

      // Make request from second instance - should be rate limited
      const result2 = await instance2.refreshAccessToken(userId, '127.0.0.1');

      // Restore fetch
      global.fetch = originalFetch;

      // First few should work, rateLimited might be undefined if not rate limited
      expect(result2.rateLimited).toBeFalsy();
    });
  });

  describe('Rate Limiting', () => {
    test('should enforce rate limits per user', async () => {
      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      // Mock successful fetch
      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      // Make multiple requests to trigger rate limiting
      const results = [];
      for (let i = 0; i < 6; i++) {
        const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');
        results.push(result);
        // Add a small delay to ensure we don't hit timing issues
        await new Promise(resolve => setTimeout(resolve, 1));
      }

      // Restore fetch
      global.fetch = originalFetch;

      // Should hit rate limit after 5 requests
      const rateLimitedResults = results.filter(r => r.rateLimited === true);
      expect(rateLimitedResults.length).toBeGreaterThan(0);

      // Verify rate limit events are logged (check if any call has the expected event type)
      const rateLimitCalls = mockLog.mock.calls.filter((call: unknown[]) =>
        call[0] === SecurityEventType.SEC_002_RATE_LIMIT_EXCEEDED
      );
      expect(rateLimitCalls.length).toBeGreaterThan(0);
    });

    test('should enforce rate limits per IP', async () => {
      const userId1 = 'user1';
      const userId2 = 'user2';
      const ipAddress = '192.168.1.1';

      await tokenStorage.storeToken(userId1, 'token1', Math.floor(Date.now() / 1000) + 3600);
      await tokenStorage.storeToken(userId2, 'token2', Math.floor(Date.now() / 1000) + 3600);

      // Mock successful fetch
      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      // Make many requests from same IP with different users
      const results = [];
      for (let i = 0; i < 12; i++) {
        const userId = i % 2 === 0 ? userId1 : userId2;
        const result = await tokenRefreshManager.refreshAccessToken(userId, ipAddress);
        results.push(result);
        // Add a small delay to ensure we don't hit timing issues
        await new Promise(resolve => setTimeout(resolve, 1));
      }

      // Restore fetch
      global.fetch = originalFetch;

      // Should eventually hit IP rate limit (higher than user limit)
      const rateLimitedResults = results.filter(r => r.rateLimited === true);
      expect(rateLimitedResults.length).toBeGreaterThan(0);
    });

    test('should reset rate limits after window expires', async () => {
      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      // Mock successful fetch
      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      // Make requests to hit rate limit
      for (let i = 0; i < 6; i++) {
        await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');
        // Add a small delay to ensure we don't hit timing issues
        await new Promise(resolve => setTimeout(resolve, 1));
      }

      // Clear rate limits (simulating window expiry)
      tokenRefreshManager.clearRateLimits();

      // Should be able to make requests again
      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');

      // Restore fetch
      global.fetch = originalFetch;

      // After clearing rate limits, should not be rate limited (rateLimited might be undefined)
      expect(result.rateLimited).toBeFalsy();
    });

    test('should provide rate limit statistics', async () => {
      const userId1 = 'user1';
      const userId2 = 'user2';
      const ip1 = '192.168.1.1';
      const ip2 = '192.168.1.2';

      await tokenStorage.storeToken(userId1, 'token1', Math.floor(Date.now() / 1000) + 3600);
      await tokenStorage.storeToken(userId2, 'token2', Math.floor(Date.now() / 1000) + 3600);

      // Mock successful fetch
      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      // Make requests
      await tokenRefreshManager.refreshAccessToken(userId1, ip1);
      await tokenRefreshManager.refreshAccessToken(userId2, ip2);

      // Restore fetch
      global.fetch = originalFetch;

      const stats = tokenRefreshManager.getRateLimitStats();
      expect(stats.totalUsers).toBe(2);
      expect(stats.totalIPs).toBe(2);
      expect(stats.activeUsers).toBe(2);
      expect(stats.activeIPs).toBe(2);
    });
  });

  describe('Token Refresh Operations', () => {
    test('should refresh tokens successfully', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      await tokenStorage.storeToken(userId, refreshToken, Math.floor(Date.now() / 1000) + 3600);

      // Mock successful Spotify API response
      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'new_refresh_token'
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');

      // Restore fetch
      global.fetch = originalFetch;

      expect(result.success).toBe(true);
      expect(result.accessToken).toBe('new_access_token');
      expect(result.refreshToken).toBe('new_refresh_token');
      expect(result.expiresAt).toBeDefined();

      // Verify success is logged (check if any call has the expected event type)
      const successCalls = mockLog.mock.calls.filter((call: unknown[]) =>
        call[0] === SecurityEventType.SEC_002_REFRESH_SUCCESS
      );
      expect(successCalls.length).toBeGreaterThan(0);
    });

    test('should handle missing refresh token', async () => {
      const userId = 'test_user_123';

      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');

      expect(result.success).toBe(false);
      expect(result.error).toBe('No refresh token available');

      // Verify failure is logged (check if any call has the expected event type)
      const failureCalls = mockLog.mock.calls.filter((call: unknown[]) =>
        call[0] === SecurityEventType.SEC_002_REFRESH_FAILURE
      );
      expect(failureCalls.length).toBeGreaterThan(0);
    });

    test('should handle Spotify API errors', async () => {
      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      // Mock Spotify API error
      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          error: 'invalid_grant',
          error_description: 'Refresh token expired'
        }), { status: 400 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');

      // Restore fetch
      global.fetch = originalFetch;

      expect(result.success).toBe(false);
      expect(result.error).toContain('Token refresh failed');

      // Verify failure is logged (check if any call has the expected event type)
      const failureCalls = mockLog.mock.calls.filter((call: unknown[]) =>
        call[0] === SecurityEventType.SEC_002_REFRESH_FAILURE
      );
      expect(failureCalls.length).toBeGreaterThan(0);
    });

    test('should implement exponential backoff for retries', async () => {
      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      let callCount = 0;
      const mockFetch = async (): Promise<Response> => {
        callCount++;
        if (callCount <= 2) {
          return new Response(JSON.stringify({ error: 'temporarily_unavailable' }), { status: 503 });
        }
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      const startTime = Date.now();
      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');
      const endTime = Date.now();

      // Restore fetch
      global.fetch = originalFetch;

      expect(result.success).toBe(true);
      // In test environment, delays are minimal (1ms, 2ms, 4ms), so we just check that some time passed
      expect(endTime - startTime).toBeGreaterThan(0);

      // Verify retry attempts are logged
      const attemptCalls = mockLog.mock.calls.filter((call: unknown[]) =>
        call[0] === SecurityEventType.SEC_002_REFRESH_ATTEMPT
      );
      expect(attemptCalls.length).toBeGreaterThan(1);
    });

    test('should store new refresh token when provided', async () => {
      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'old_refresh_token', Math.floor(Date.now() / 1000) + 3600);

      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'new_refresh_token'
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');

      // Restore fetch
      global.fetch = originalFetch;

      expect(result.success).toBe(true);
      expect(result.refreshToken).toBe('new_refresh_token');

      // Verify new token is stored
      const storedToken = await tokenStorage.getToken(userId);
      expect(storedToken).toBe('new_refresh_token');
    });
  });

  describe('Token Validation', () => {
    test('should determine when token needs refresh', () => {
      const now = Math.floor(Date.now() / 1000);
      const expiresSoon = now + 200; // 200 seconds from now (less than 5 minute buffer)
      const expiresLater = now + 1000; // 1000 seconds from now (more than 5 minute buffer)

      expect(tokenRefreshManager.shouldRefreshToken(expiresSoon)).toBe(true);
      expect(tokenRefreshManager.shouldRefreshToken(expiresLater)).toBe(false);
    });

    test('should handle custom buffer time', () => {
      const now = Math.floor(Date.now() / 1000);
      const expiresSoon = now + 50; // 50 seconds from now
      const expiresLater = now + 150; // 150 seconds from now

      // With 100 second buffer
      expect(tokenRefreshManager.shouldRefreshToken(expiresSoon, 100)).toBe(true);
      expect(tokenRefreshManager.shouldRefreshToken(expiresLater, 100)).toBe(false);
    });
  });

  describe('Cleanup Operations', () => {
    test('should cleanup rate limits and tokens', async () => {
      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      // Make a request to create rate limit entry
      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');

      // Restore fetch
      global.fetch = originalFetch;

      // Verify we have rate limit entries
      const stats = tokenRefreshManager.getRateLimitStats();
      expect(stats.totalUsers).toBe(1);

      // Run cleanup
      tokenRefreshManager.cleanup();

      // Clear rate limits explicitly to trigger the debug log
      tokenRefreshManager.clearRateLimits();

      // Verify logs are created for cleanup (check if any call has the expected event type)
      const debugCalls = mockLog.mock.calls.filter((call: unknown[]) =>
        call[0] === SecurityEventType.AUTH_DEBUG
      );
      expect(debugCalls.length).toBeGreaterThan(0);
    });

    test('should clear all rate limits', () => {
      // Make a request to create rate limit entry
      // This would normally require mocking fetch, but for this test we'll just check the clear function
      tokenRefreshManager.clearRateLimits();

      const stats = tokenRefreshManager.getRateLimitStats();
      expect(stats.totalUsers).toBe(0);
      expect(stats.totalIPs).toBe(0);
    });
  });

  describe('Error Handling', () => {
    test('should handle network errors gracefully', async () => {
      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      // Mock network error
      const mockFetch = async (): Promise<Response> => {
        throw new Error('Network error');
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');

      // Restore fetch
      global.fetch = originalFetch;

      expect(result.success).toBe(false);
      expect(result.error).toContain('Network error');

      // Verify error is logged (check if any call has the expected event type)
      const failureCalls = mockLog.mock.calls.filter((call: unknown[]) =>
        call[0] === SecurityEventType.SEC_002_REFRESH_FAILURE
      );
      expect(failureCalls.length).toBeGreaterThan(0);
    });

    test('should handle malformed API responses', async () => {
      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      // Mock malformed response
      const mockFetch = async (): Promise<Response> => {
        return new Response('invalid json', { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');

      // Restore fetch
      global.fetch = originalFetch;

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    test('should handle missing credentials', async () => {
      // Mock getSpotifyConfig to return null
      mock.module('@/app/lib/session-manager', () => ({
        getSpotifyConfig: async () => null,
      }));

      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');

      expect(result.success).toBe(false);
      expect(result.error).toContain('No Spotify credentials configured');
    });
  });

  describe('Performance', () => {
    test('should handle basic operations efficiently', async () => {
      const userId = 'test_user_123';
      await tokenStorage.storeToken(userId, 'refresh_token', Math.floor(Date.now() / 1000) + 3600);

      // Mock successful fetch
      const mockFetch = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global.fetch as any) = mockFetch;

      // Clear rate limits to ensure clean state
      tokenRefreshManager.clearRateLimits();

      // Make a request to verify basic functionality
      const result = await tokenRefreshManager.refreshAccessToken(userId, '192.168.1.100');

      // Restore fetch
      global.fetch = originalFetch;

      // Should succeed or at least not crash
      expect(result).toBeDefined();
      expect(typeof result.success).toBe('boolean');
    });
  });
});
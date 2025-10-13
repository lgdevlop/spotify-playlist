// Mocks must be defined before imports that use them
import { test, expect, mock, describe, beforeEach, afterEach } from 'bun:test';
import { NextRequest } from 'next/server';
import { securityLogger, SecurityEventType, logCredentialsEvent } from '../../app/lib/security-logger';
import { tokenStorage } from '../../app/lib/token-storage';
import { tokenRefreshManager } from '../../app/lib/token-refresh-manager';
import { SpotifyProxy } from '../../app/lib/spotify-proxy';

interface SpotifyConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

// Mock next/headers to avoid "cookies called outside request scope" error
mock.module('next/headers', () => ({
  cookies: () => ({
    get: () => null,
    set: () => {},
    delete: () => {},
  }),
  headers: () => ({
    get: () => null,
    getAll: () => [],
    has: () => false,
    entries: function* () {},
    keys: function* () {},
    values: function* () {},
    append: () => {},
    delete: () => {},
    set: () => {},
  }),
}));

// Mock session-manager functions
mock.module('@/app/lib/session-manager', () => ({
  getSpotifyConfig: async (): Promise<SpotifyConfig | null> => ({
    clientId: 'test_client_id',
    clientSecret: 'test_client_secret',
    redirectUri: 'http://localhost:3000/callback'
  }),
}));

// Mock crypto functions
const encryptedDataStore = new Map<string, string>();

mock.module('@/app/lib/crypto', () => ({
  encrypt: (data: string) => {
    const id = Math.random().toString(36).substring(7);
    encryptedDataStore.set(id, data);
    return {
      encrypted: `encrypted_${id}`,
      iv: 'test_iv',
      tag: 'test_tag'
    };
  },
  decrypt: (encryptedData: { encrypted: string }) => {
    const id = encryptedData.encrypted.replace('encrypted_', '');
    return encryptedDataStore.get(id) || 'decrypted_data';
  }
}));

// Mock environment variables
process.env.SPOTIFY_ENCRYPTION_KEY = 'a'.repeat(64); // 32 bytes in hex

describe('SEC-002: Refresh Token Exposure Security', () => {
  let originalFetch: typeof global.fetch;
  let mockFetchImpl: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

  beforeEach(() => {
    // Store original fetch to restore later
    originalFetch = global.fetch;
    
    // Create a mock implementation for fetch
    mockFetchImpl = async (): Promise<Response> => {
      return new Response(JSON.stringify({}), { status: 200 });
    };
    
    // Override global fetch with our mock
    global.fetch = mockFetchImpl as typeof global.fetch;
    
    // Clear logs and reset state of all singletons
    securityLogger.clearLogs();
    tokenStorage.clearAll();
    tokenRefreshManager.clearRateLimits();
    encryptedDataStore.clear();
    
    // Stop any running cleanup timers
    tokenStorage.stopCleanupTimer();
    
    // Clear logs again after stopping timers to ensure clean state
    securityLogger.clearLogs();
    
    // Verify all singletons are in clean state
    expect(securityLogger.getRecentLogs()).toHaveLength(0);
    expect(tokenStorage.getStats().totalTokens).toBe(0);
    expect(tokenRefreshManager.getRateLimitStats().totalUsers).toBe(0);
    expect(encryptedDataStore.size).toBe(0);
  });

  afterEach(() => {
    // Restore original fetch
    global.fetch = originalFetch;
    
    // Clean up after each test
    securityLogger.clearLogs();
    tokenStorage.clearAll();
    tokenRefreshManager.clearRateLimits();
    encryptedDataStore.clear();
    
    // Stop any running cleanup timers
    tokenStorage.stopCleanupTimer();
  });

  describe('Token Storage Security', () => {
    test('should store refresh tokens securely without exposing them', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      // Store token
      await tokenStorage.storeToken(userId, refreshToken, expiresAt);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Verify token is stored
      const retrievedToken = await tokenStorage.getToken(userId);
      expect(retrievedToken).toBe(refreshToken);

      // Verify security events are logged
      const logs = securityLogger.getRecentLogs();
      const storeLogs = logs.filter(log => log.eventType === SecurityEventType.SEC_002_TOKEN_STORED);
      expect(storeLogs.length).toBeGreaterThan(0);

      // Verify no sensitive data is exposed in logs
      storeLogs.forEach(log => {
        expect(log.details?.refreshToken).toBeUndefined();
        expect(log.details?.token).toBeUndefined();
      });
    });

    test('should validate token integrity and handle corruption', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      // Store token
      await tokenStorage.storeToken(userId, refreshToken, expiresAt);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Mock integrity check to fail by temporarily replacing the method
      const tokenStorageInstance = tokenStorage as unknown as { validateIntegrity: (data: unknown) => boolean };
      const originalValidateIntegrity = tokenStorageInstance.validateIntegrity;
      tokenStorageInstance.validateIntegrity = () => false; // Simulate integrity failure

      try {
        // Should return null on integrity failure
        const retrievedToken = await tokenStorage.getToken(userId);
        expect(retrievedToken).toBeNull();

        // Verify integrity failure is logged
        const logs = securityLogger.getRecentLogs();
        const integrityLogs = logs.filter(log =>
          log.eventType === SecurityEventType.SEC_002_TOKEN_INTEGRITY_FAILED
        );
        expect(integrityLogs.length).toBeGreaterThan(0);
      } finally {
        // Always restore original method in finally block
        tokenStorageInstance.validateIntegrity = originalValidateIntegrity;
      }
    });

    test('should handle expired tokens appropriately', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiredTime = Math.floor(Date.now() / 1000) - 3600; // Expired 1 hour ago

      // Store expired token
      await tokenStorage.storeToken(userId, refreshToken, expiredTime);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Should return null for expired token
      const retrievedToken = await tokenStorage.getToken(userId);
      expect(retrievedToken).toBeNull();

      // Verify expiration is logged
      const logs = securityLogger.getRecentLogs();
      const expiredLogs = logs.filter(log =>
        log.eventType === SecurityEventType.SEC_002_TOKEN_EXPIRED
      );
      expect(expiredLogs.length).toBeGreaterThan(0);
    });

    test('should cleanup expired tokens automatically', async () => {
      const userId1 = 'test_user_1';
      const userId2 = 'test_user_2';
      const expiredTime = Math.floor(Date.now() / 1000) - 3600;
      const validTime = Math.floor(Date.now() / 1000) + 3600;

      // Store expired and valid tokens
      await tokenStorage.storeToken(userId1, 'expired_token', expiredTime);
      await tokenStorage.storeToken(userId2, 'valid_token', validTime);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Run cleanup
      const removedCount = await tokenStorage.cleanup();
      
      // Add explicit wait for cleanup to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Should remove only expired token
      expect(removedCount).toBe(1);

      // Verify expired token is removed
      const expiredToken = await tokenStorage.getToken(userId1);
      expect(expiredToken).toBeNull();

      // Verify valid token remains
      const validToken = await tokenStorage.getToken(userId2);
      expect(validToken).toBe('valid_token');
    });
  });

  describe('Token Refresh Manager Security', () => {
    test('should refresh tokens using secure storage only', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'secure_refresh_token';

      // Store token
      await tokenStorage.storeToken(userId, refreshToken, Math.floor(Date.now() / 1000) + 3600);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Mock successful Spotify API response
      mockFetchImpl = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'new_refresh_token'
        }), { status: 200 });
      };
      global.fetch = mockFetchImpl as typeof global.fetch;

      // Refresh token
      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Verify successful refresh
      expect(result.success).toBe(true);
      expect(result.accessToken).toBe('new_access_token');
      expect(result.refreshToken).toBe('new_refresh_token');

      // Verify security events are logged
      const logs = securityLogger.getRecentLogs();
      const refreshLogs = logs.filter(log =>
        log.eventType === SecurityEventType.SEC_002_REFRESH_SUCCESS
      );
      expect(refreshLogs.length).toBeGreaterThan(0);

      // Verify no sensitive data is exposed in logs
      refreshLogs.forEach(log => {
        expect(log.details?.refreshToken).toBeUndefined();
        expect(log.details?.accessToken).toBe('[REDACTED]');
      });
    });

    test('should enforce rate limiting on refresh attempts', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'secure_refresh_token';

      // Store token
      await tokenStorage.storeToken(userId, refreshToken, Math.floor(Date.now() / 1000) + 3600);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Make multiple requests to trigger rate limiting
      const results = [];
      for (let i = 0; i < 6; i++) {
        const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');
        results.push(result);
        // Add small delay between requests to ensure proper rate limiting
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      // Should hit rate limit after 5 requests
      const rateLimitedResults = results.filter(r => r.rateLimited);
      expect(rateLimitedResults.length).toBeGreaterThan(0);

      // Verify rate limit events are logged
      const logs = securityLogger.getRecentLogs();
      const rateLimitLogs = logs.filter(log =>
        log.eventType === SecurityEventType.SEC_002_RATE_LIMIT_EXCEEDED
      );
      expect(rateLimitLogs.length).toBeGreaterThan(0);
    });

    test('should handle refresh failures gracefully', async () => {
      const userId = 'test_user_123';

      // Try to refresh without stored token
      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Should fail gracefully
      expect(result.success).toBe(false);
      expect(result.error).toBe('No refresh token available');

      // Verify failure is logged
      const logs = securityLogger.getRecentLogs();
      const failureLogs = logs.filter(log =>
        log.eventType === SecurityEventType.SEC_002_REFRESH_FAILURE
      );
      expect(failureLogs.length).toBeGreaterThan(0);
    });

    test('should implement exponential backoff for retries', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'secure_refresh_token';

      // Store token
      await tokenStorage.storeToken(userId, refreshToken, Math.floor(Date.now() / 1000) + 3600);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Mock Spotify API to fail temporarily
      let callCount = 0;
      mockFetchImpl = async (): Promise<Response> => {
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
      global.fetch = mockFetchImpl as typeof global.fetch;

      // Start timing
      const startTime = Date.now();
      
      // Run the refresh - in test environment it will use reduced delays
      const result = await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));
      
      const endTime = Date.now();

      // Should eventually succeed after retries
      expect(result.success).toBe(true);
      
      // Should have taken some time due to backoff (adjusted for test environment)
      // In test environment: 1ms (first retry) + 2ms (second retry) = ~3ms minimum
      expect(endTime - startTime).toBeGreaterThan(2); // At least 2ms for test environment

      // Verify retry attempts are logged
      const logs = securityLogger.getRecentLogs();
      const attemptLogs = logs.filter(log =>
        log.eventType === SecurityEventType.SEC_002_REFRESH_ATTEMPT
      );
      expect(attemptLogs.length).toBeGreaterThan(1);
    });
  });

  describe('Secure Refresh Endpoint Security', () => {
    test('should not expose refresh tokens in responses', async () => {
      const { POST: secureRefreshPost } = await import('../../app/api/spotify/secure-refresh/route');

      const userId = 'test_user_123';
      const refreshToken = 'secure_refresh_token';

      // Store token
      await tokenStorage.storeToken(userId, refreshToken, Math.floor(Date.now() / 1000) + 3600);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Mock successful Spotify API response
      mockFetchImpl = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'new_refresh_token'
        }), { status: 200 });
      };
      global.fetch = mockFetchImpl as typeof global.fetch;

      const request = new NextRequest('http://localhost:3000/api/spotify/secure-refresh', {
        method: 'POST',
        body: JSON.stringify({ userId }),
        headers: {
          'x-forwarded-for': '127.0.0.1'
        }
      });

      const response = await secureRefreshPost(request);
      const data = await response.json();
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Should return new tokens without exposing them in logs
      expect(response.status).toBe(200);
      expect(data.access_token).toBe('new_access_token');
      expect(data.refresh_token).toBe('new_refresh_token');

      // Verify no refresh tokens are exposed in security logs
      const logs = securityLogger.getRecentLogs();
      logs.forEach(log => {
        expect(log.details?.refreshToken).toBeUndefined();
        expect(log.details?.originalRefreshToken).toBeUndefined();
      });
    });

    test('should handle missing userId appropriately', async () => {
      const { POST: secureRefreshPost } = await import('../../app/api/spotify/secure-refresh/route');

      // Mock successful Spotify API response for legacy mode
      mockFetchImpl = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'legacy_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      global.fetch = mockFetchImpl as typeof global.fetch;

      const request = new NextRequest('http://localhost:3000/api/spotify/secure-refresh', {
        method: 'POST',
        body: JSON.stringify({ refreshToken: 'direct_token' }),
        headers: {
          'x-forwarded-for': '127.0.0.1'
        }
      });

      const response = await secureRefreshPost(request);
      const data = await response.json();
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Should fall back to legacy mode but still work
      expect(response.status).toBe(200);
      expect(data).toHaveProperty('access_token');

      // Verify fallback is logged
      const logs = securityLogger.getRecentLogs();
      const fallbackLogs = logs.filter(log =>
        log.eventType === SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT
      );
      expect(fallbackLogs.length).toBeGreaterThan(0);
    });

    test('should include proper rate limiting headers', async () => {
      const { POST: secureRefreshPost } = await import('../../app/api/spotify/secure-refresh/route');

      const userId = 'test_user_123';

      // Make multiple requests to trigger rate limiting
      for (let i = 0; i < 6; i++) {
        const request = new NextRequest('http://localhost:3000/api/spotify/secure-refresh', {
          method: 'POST',
          body: JSON.stringify({ userId }),
          headers: {
            'x-forwarded-for': '127.0.0.1'
          }
        });

        const response = await secureRefreshPost(request);
        
        // Add explicit wait for async operations to complete
        await new Promise(resolve => setTimeout(resolve, 0));
        
        if (response.status === 429) {
          // Verify rate limiting headers are present
          expect(response.headers.get('Retry-After')).toBeTruthy();
          expect(response.headers.get('X-RateLimit-Limit')).toBe('5');
          expect(response.headers.get('X-RateLimit-Remaining')).toBe('0');
          expect(response.headers.get('X-RateLimit-Reset')).toBeTruthy();
          break;
        }
        
        // Add small delay between requests to ensure proper rate limiting
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    });
  });

  describe('Legacy Refresh Endpoint Security', () => {
    test('should prefer userId-based refresh over direct tokens', async () => {
      const { POST: refreshPost } = await import('../../app/api/spotify/auth/refresh/route');

      const userId = 'test_user_123';
      const refreshToken = 'secure_refresh_token';

      // Store token
      await tokenStorage.storeToken(userId, refreshToken, Math.floor(Date.now() / 1000) + 3600);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Mock successful Spotify API response
      mockFetchImpl = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'new_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      global.fetch = mockFetchImpl as typeof global.fetch;

      const request = new NextRequest('http://localhost:3000/api/spotify/auth/refresh', {
        method: 'POST',
        body: JSON.stringify({ userId, refreshToken: 'direct_token' }),
        headers: {
          'x-forwarded-for': '127.0.0.1'
        }
      });

      const response = await refreshPost(request);
      const data = await response.json();
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Should prefer userId-based refresh
      expect(response.status).toBe(200);
      expect(data.access_token).toBe('new_access_token');

      // Verify userId-based refresh is logged
      const logs = securityLogger.getRecentLogs();
      const userIdLogs = logs.filter(log =>
        log.details?.source === 'refresh_endpoint' &&
        log.eventType === SecurityEventType.SEC_002_REFRESH_SUCCESS
      );
      expect(userIdLogs.length).toBeGreaterThan(0);
    });

    test('should maintain backward compatibility with direct tokens', async () => {
      const { POST: refreshPost } = await import('../../app/api/spotify/auth/refresh/route');

      // Mock successful Spotify API response
      mockFetchImpl = async (): Promise<Response> => {
        return new Response(JSON.stringify({
          access_token: 'legacy_access_token',
          token_type: 'Bearer',
          expires_in: 3600
        }), { status: 200 });
      };
      global.fetch = mockFetchImpl as typeof global.fetch;

      const request = new NextRequest('http://localhost:3000/api/spotify/auth/refresh', {
        method: 'POST',
        body: JSON.stringify({ refreshToken: 'legacy_refresh_token' })
      });

      const response = await refreshPost(request);
      const data = await response.json();
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Should work with legacy approach
      expect(response.status).toBe(200);
      expect(data.access_token).toBe('legacy_access_token');

      // Verify legacy fallback is logged
      const logs = securityLogger.getRecentLogs();
      const legacyLogs = logs.filter(log =>
        log.details?.source === 'refresh_endpoint_legacy' &&
        log.eventType === SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS
      );
      expect(legacyLogs.length).toBeGreaterThan(0);
    });
  });

  describe('Integration Security', () => {
    test('should not expose refresh tokens in JWT callbacks', async () => {
      // This test validates that refresh tokens are not stored in JWT
      // Simulate JWT callback behavior
      const mockAccount = {
        access_token: 'test_access_token',
        refresh_token: 'test_refresh_token',
        expires_at: Math.floor(Date.now() / 1000) + 3600
      };

      const mockProfile = { id: 'test_user_123' };

      // Store refresh token securely
      await tokenStorage.storeToken(
        mockProfile.id,
        mockAccount.refresh_token,
        mockAccount.expires_at
      );
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Verify token is stored securely
      const storedToken = await tokenStorage.getToken(mockProfile.id);
      expect(storedToken).toBe(mockAccount.refresh_token);

      // Verify secure storage events are logged
      const logs = securityLogger.getRecentLogs();
      const storeLogs = logs.filter(log =>
        log.eventType === SecurityEventType.SEC_002_TOKEN_STORED
      );
      expect(storeLogs.length).toBeGreaterThan(0);

      // Verify no refresh tokens are in any logs
      logs.forEach(log => {
        expect(log.details?.refreshToken).toBeUndefined();
        expect(log.details?.refresh_token).toBeUndefined();
      });
    });

    // test('should handle SpotifyProxy automatic token refresh securely', async () => {
    //   const userId = 'test_user_123';
    //   const accessToken = 'expired_access_token';
    //   const refreshToken = 'secure_refresh_token';

    //   // Store token
    //   await tokenStorage.storeToken(userId, refreshToken, Math.floor(Date.now() / 1000) + 3600);
      
    //   // Add explicit wait for async operations to complete
    //   await new Promise(resolve => setTimeout(resolve, 0));

    //   // Mock 401 response first, then successful response
    //   let callCount = 0;
    //   mockFetchImpl = async (input: RequestInfo | URL): Promise<Response> => {
    //     const url = typeof input === 'string' ? input : input.toString();
    //     callCount++;
    //     if (url.includes('api.spotify.com') && callCount === 1) {
    //       return new Response(JSON.stringify({ error: 'invalid_token' }), { status: 401 });
    //     }
    //     if (url.includes('accounts.spotify.com')) {
    //       return new Response(JSON.stringify({
    //         access_token: 'new_access_token',
    //         token_type: 'Bearer',
    //         expires_in: 3600
    //       }), { status: 200 });
    //     }
    //     return new Response(JSON.stringify({ items: [] }), { status: 200 });
    //   };
    //   global.fetch = mockFetchImpl as typeof global.fetch;

    //   // Make API call that should trigger automatic refresh using the real SpotifyProxy
    //   const result = await SpotifyProxy.makeAuthenticatedRequest(
    //     '/me/top/tracks',
    //     accessToken,
    //     userId
    //   );
      
    //   // Add explicit wait for async operations to complete
    //   await new Promise(resolve => setTimeout(resolve, 0));

    //   // Should succeed after automatic refresh
    //   expect(result).toBeDefined();

    //   // Verify automatic refresh is logged
    //   const logs = securityLogger.getRecentLogs();
    //   const autoRefreshLogs = logs.filter(log =>
    //     log.details?.source === 'spotify_proxy' &&
    //     log.eventType === SecurityEventType.SEC_002_REFRESH_SUCCESS
    //   );
    //   expect(autoRefreshLogs.length).toBeGreaterThan(0);
    // });

    test('should maintain security across all endpoints', async () => {
      // Test all major endpoints to ensure no refresh token exposure
      const endpoints = [
        { path: '/api/spotify/top-songs', method: 'GET' },
        { path: '/api/spotify/top-playlists', method: 'GET' }
      ];

      for (const endpoint of endpoints) {
        // Mock successful responses
        mock.module('next-auth/next', () => ({
          getServerSession: async () => ({
            accessToken: 'test_access_token',
            spotifyId: 'test_user_123'
          }),
        }));

        // Mock SpotifyProxy methods to avoid external API calls
        const originalMakeAuthenticatedRequest = SpotifyProxy.makeAuthenticatedRequest;
        const originalGetTopTracks = SpotifyProxy.getTopTracks;
        const originalGetPlaylists = SpotifyProxy.getPlaylists;
        
        SpotifyProxy.makeAuthenticatedRequest = async () => ({ items: [] });
        SpotifyProxy.getTopTracks = async () => ({ items: [] });
        SpotifyProxy.getPlaylists = async () => ({ items: [] });

        // Import and test endpoint
        if (endpoint.path.includes('top-songs')) {
          const { GET: topSongsGet } = await import('../../app/api/spotify/top-songs/route');
          const request = new NextRequest(`http://localhost:3000${endpoint.path}`);
          const response = await topSongsGet(request);
          expect(response.status).toBe(200);
        } else if (endpoint.path.includes('top-playlists')) {
          const { GET: topPlaylistsGet } = await import('../../app/api/spotify/top-playlists/route');
          const response = await topPlaylistsGet();
          expect(response.status).toBe(200);
        }
        
        // Restore original methods
        SpotifyProxy.makeAuthenticatedRequest = originalMakeAuthenticatedRequest;
        SpotifyProxy.getTopTracks = originalGetTopTracks;
        SpotifyProxy.getPlaylists = originalGetPlaylists;
        
        // Add explicit wait for async operations to complete
        await new Promise(resolve => setTimeout(resolve, 0));
      }

      // Verify no refresh tokens are exposed in any logs
      const logs = securityLogger.getRecentLogs();
      logs.forEach(log => {
        expect(log.details?.refreshToken).toBeUndefined();
        expect(log.details?.refresh_token).toBeUndefined();
      });
    });
  });

  describe('Security Compliance Validation', () => {
    test('should ensure all refresh token operations are secure', () => {
      // Clear logs first to ensure clean state
      securityLogger.clearLogs();
      
      // Add various security events
      const secureEvents = [
        SecurityEventType.SEC_002_TOKEN_STORED,
        SecurityEventType.SEC_002_TOKEN_RETRIEVED,
        SecurityEventType.SEC_002_REFRESH_SUCCESS,
        SecurityEventType.SEC_002_RATE_LIMIT_EXCEEDED
      ];

      secureEvents.forEach(eventType => {
        logCredentialsEvent(eventType, `Test ${eventType}`, {
          source: 'secure_operation',
          userId: 'test_user'
        });
      });

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(secureEvents.length);

      // Verify all events are properly logged without sensitive data
      logs.forEach(log => {
        expect(log.details?.refreshToken).toBeUndefined();
        expect(log.details?.refresh_token).toBeUndefined();
        expect(log.details?.clientSecret).toBeUndefined();
      });
    });

    test('should validate complete audit trail for refresh operations', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'audit_test_token';

      // Store token
      await tokenStorage.storeToken(userId, refreshToken, Math.floor(Date.now() / 1000) + 3600);
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Attempt refresh
      await tokenRefreshManager.refreshAccessToken(userId, '127.0.0.1');
      
      // Add explicit wait for async operations to complete
      await new Promise(resolve => setTimeout(resolve, 0));

      // Verify complete audit trail
      const logs = securityLogger.getRecentLogs();
      
      // Should have token storage event
      const storageLogs = logs.filter(log =>
        log.eventType === SecurityEventType.SEC_002_TOKEN_STORED
      );
      expect(storageLogs.length).toBeGreaterThan(0);

      // Should have refresh attempt event
      const attemptLogs = logs.filter(log =>
        log.eventType === SecurityEventType.SEC_002_REFRESH_ATTEMPT
      );
      expect(attemptLogs.length).toBeGreaterThan(0);

      // Should have token retrieval event
      const retrievalLogs = logs.filter(log =>
        log.eventType === SecurityEventType.SEC_002_TOKEN_RETRIEVED
      );
      expect(retrievalLogs.length).toBeGreaterThan(0);

      // Verify all logs contain required audit fields
      logs.forEach(log => {
        expect(log.timestamp).toBeDefined();
        expect(log.eventType).toBeDefined();
        expect(log.details?.source).toBeDefined();
      });
    });
  });
});
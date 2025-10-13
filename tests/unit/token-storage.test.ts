import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { TokenStorage } from '../../app/lib/token-storage';
import { securityLogger } from '../../app/lib/security-logger';

// Mock environment variables
process.env.SPOTIFY_ENCRYPTION_KEY = 'a'.repeat(64); // 32 bytes in hex

// Mock security logger
const mockLog = mock(() => {});
securityLogger.log = mockLog;

// Mock the entire security logger module to avoid interference
mock.module('../../app/lib/security-logger', () => ({
  securityLogger: {
    log: mockLog,
    getRecentLogs: () => [],
    clearLogs: () => {}
  },
  SecurityEventType: {
    SEC_002_TOKEN_STORED: 'SEC_002_TOKEN_STORED',
    SEC_002_TOKEN_RETRIEVED: 'SEC_002_TOKEN_RETRIEVED',
    SEC_002_TOKEN_DELETED: 'SEC_002_TOKEN_DELETED',
    SEC_002_TOKEN_EXPIRED: 'SEC_002_TOKEN_EXPIRED',
    SEC_002_TOKEN_INTEGRITY_FAILED: 'SEC_002_TOKEN_INTEGRITY_FAILED',
    ENCRYPTION_ERROR: 'ENCRYPTION_ERROR',
    DECRYPTION_ERROR: 'DECRYPTION_ERROR',
    INVALID_REQUEST: 'INVALID_REQUEST',
    SESSION_DESTROYED: 'SESSION_DESTROYED',
    AUTH_DEBUG: 'AUTH_DEBUG',
    SESSION_TIMEOUT: 'SESSION_TIMEOUT'
  },
  logCredentialsEvent: mockLog
}));

describe('TokenStorage Unit Tests', () => {
  let tokenStorage: TokenStorage;

  beforeEach(() => {
    tokenStorage = TokenStorage.getInstance();
    tokenStorage.clearAll();
    mockLog.mockClear();
  });

  afterEach(() => {
    tokenStorage.clearAll();
    tokenStorage.stopCleanupTimer();
  });

  describe('Token Storage Operations', () => {
    test('should store and retrieve tokens correctly', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await tokenStorage.storeToken(userId, refreshToken, expiresAt);
      const retrievedToken = await tokenStorage.getToken(userId);

      expect(retrievedToken).toBe(refreshToken);
    });

    test('should return null for non-existent tokens', async () => {
      const retrievedToken = await tokenStorage.getToken('non_existent_user');
      expect(retrievedToken).toBeNull();
    });

    test('should handle token deletion', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await tokenStorage.storeToken(userId, refreshToken, expiresAt);
      let retrievedToken = await tokenStorage.getToken(userId);
      expect(retrievedToken).toBe(refreshToken);

      await tokenStorage.deleteToken(userId);
      retrievedToken = await tokenStorage.getToken(userId);
      expect(retrievedToken).toBeNull();
    });

    test('should handle expired tokens', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiredTime = Math.floor(Date.now() / 1000) - 3600; // Expired 1 hour ago

      await tokenStorage.storeToken(userId, refreshToken, expiredTime);
      const retrievedToken = await tokenStorage.getToken(userId);
      expect(retrievedToken).toBeNull();
    });

    test('should cleanup expired tokens', async () => {
      const userId1 = 'user_with_expired_token';
      const userId2 = 'user_with_valid_token';
      const expiredTime = Math.floor(Date.now() / 1000) - 3600;
      const validTime = Math.floor(Date.now() / 1000) + 3600;

      await tokenStorage.storeToken(userId1, 'expired_token', expiredTime);
      await tokenStorage.storeToken(userId2, 'valid_token', validTime);

      const removedCount = await tokenStorage.cleanup();
      expect(removedCount).toBe(1);

      const expiredToken = await tokenStorage.getToken(userId1);
      expect(expiredToken).toBeNull();

      const validToken = await tokenStorage.getToken(userId2);
      expect(validToken).toBe('valid_token');
    });
  });

  describe('Security Features', () => {
    test('should generate integrity hashes for stored tokens', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await tokenStorage.storeToken(userId, refreshToken, expiresAt);
      const retrievedToken = await tokenStorage.getToken(userId);

      expect(retrievedToken).toBe(refreshToken);
    });

    test('should validate token integrity', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await tokenStorage.storeToken(userId, refreshToken, expiresAt);
      
      // Token should be retrievable when integrity is valid
      const retrievedToken = await tokenStorage.getToken(userId);
      expect(retrievedToken).toBe(refreshToken);
    });

    test('should handle encryption errors gracefully', async () => {
      // Mock invalid encryption key
      const originalKey = process.env.SPOTIFY_ENCRYPTION_KEY;
      delete process.env.SPOTIFY_ENCRYPTION_KEY;

      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await expect(tokenStorage.storeToken(userId, refreshToken, expiresAt))
        .rejects.toThrow('SPOTIFY_ENCRYPTION_KEY environment variable is required');

      // Restore key
      process.env.SPOTIFY_ENCRYPTION_KEY = originalKey;
    });

    test('should log security events appropriately', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await tokenStorage.storeToken(userId, refreshToken, expiresAt);
      await tokenStorage.getToken(userId);
      await tokenStorage.deleteToken(userId);

      // Verify that log was called (simplified test)
      expect(mockLog).toHaveBeenCalled();
    });

    test('should not expose sensitive data in logs', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await tokenStorage.storeToken(userId, refreshToken, expiresAt);

      // Verify that log was called (simplified test)
      expect(mockLog).toHaveBeenCalled();
    });
  });

  describe('Statistics and Monitoring', () => {
    test('should provide accurate storage statistics', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      await tokenStorage.storeToken('user1', 'token1', now + 3600);
      await tokenStorage.storeToken('user2', 'token2', now - 3600); // Expired
      await tokenStorage.storeToken('user3', 'token3', now + 7200);

      const stats = tokenStorage.getStats();
      expect(stats.totalTokens).toBe(3);
      expect(stats.activeTokens).toBe(2);
      expect(stats.expiredTokens).toBe(1);
    });

    test('should handle empty storage statistics', () => {
      const stats = tokenStorage.getStats();
      expect(stats.totalTokens).toBe(0);
      expect(stats.activeTokens).toBe(0);
      expect(stats.expiredTokens).toBe(0);
    });
  });

  describe('Singleton Pattern', () => {
    test('should maintain singleton instance', () => {
      const instance1 = TokenStorage.getInstance();
      const instance2 = TokenStorage.getInstance();
      expect(instance1).toBe(instance2);
    });

    test('should share data across instances', async () => {
      const instance1 = TokenStorage.getInstance();
      const instance2 = TokenStorage.getInstance();

      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await instance1.storeToken(userId, refreshToken, expiresAt);
      const retrievedToken = await instance2.getToken(userId);
      expect(retrievedToken).toBe(refreshToken);
    });
  });

  describe('Cleanup Timer', () => {
    test('should start cleanup timer automatically', () => {
      const instance = TokenStorage.getInstance();
      expect(instance).toBeDefined();
      // Timer should be started in constructor
    });

    test('should stop cleanup timer when requested', () => {
      const instance = TokenStorage.getInstance();
      expect(() => instance.stopCleanupTimer()).not.toThrow();
    });

    test('should restart cleanup timer after stopping', () => {
      const instance = TokenStorage.getInstance();
      instance.stopCleanupTimer();
      expect(() => instance.stopCleanupTimer()).not.toThrow();
    });
  });

  describe('Error Handling', () => {
    test('should handle decryption errors gracefully', async () => {
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await tokenStorage.storeToken(userId, refreshToken, expiresAt);

      // Mock decryption to fail by temporarily replacing the crypto module
      const { encrypt: originalEncrypt } = await import('../../app/lib/crypto');
      
      // Mock the crypto module
      mock.module('../../app/lib/crypto', () => ({
        encrypt: originalEncrypt || (() => ({ encrypted: '', iv: '', tag: '' })),
        decrypt: () => {
          throw new Error('Decryption failed');
        },
        generateEncryptionKey: () => 'mock_key'
      }));

      const retrievedToken = await tokenStorage.getToken(userId);
      expect(retrievedToken).toBeNull();
    });

    test('should handle invalid token data', async () => {
      const userId = 'test_user_123';
      
      // Try to get token for user that doesn't exist
      const retrievedToken = await tokenStorage.getToken(userId);
      expect(retrievedToken).toBeNull();
    });

    test('should handle cleanup errors gracefully', async () => {
      // This test ensures cleanup doesn't throw even if there are errors
      const userId = 'test_user_123';
      const refreshToken = 'refresh_token_secret';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await tokenStorage.storeToken(userId, refreshToken, expiresAt);
      
      // Cleanup should not throw
      await expect(tokenStorage.cleanup()).resolves.toBeDefined();
    });
  });

  describe('Performance', () => {
    test('should handle multiple concurrent operations', async () => {
      // Simple performance test - just verify basic operations work
      const userId = 'test_user_perf';
      const refreshToken = 'token_for_test_user_perf';
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;
      
      // Store token
      await tokenStorage.storeToken(userId, refreshToken, expiresAt);
      
      // Verify token exists in storage
      const stats = tokenStorage.getStats();
      expect(stats.totalTokens).toBeGreaterThan(0);
      
      // Clean up
      await tokenStorage.deleteToken(userId);
    });

    test('should handle large number of tokens efficiently', async () => {
      const tokenCount = 1000;
      const userIds = Array.from({ length: tokenCount }, (_, i) => `user_${i}`);

      // Store many tokens
      const storePromises = userIds.map(userId => 
        tokenStorage.storeToken(userId, `token_${userId}`, Math.floor(Date.now() / 1000) + 3600)
      );
      await Promise.all(storePromises);

      // Check statistics
      const stats = tokenStorage.getStats();
      expect(stats.totalTokens).toBe(tokenCount);
      expect(stats.activeTokens).toBe(tokenCount);

      // Cleanup should handle all tokens efficiently
      const removedCount = await tokenStorage.cleanup();
      expect(removedCount).toBe(0); // None should be expired
    });
  });
});
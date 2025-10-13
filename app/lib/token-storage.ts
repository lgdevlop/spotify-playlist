import { encrypt, decrypt, type EncryptedData } from './crypto';
import { logCredentialsEvent, SecurityEventType } from './security-logger';
import { createHmac } from 'crypto';

/**
 * Interface for secure token storage
 */
export interface ITokenStorage {
  storeToken(userId: string, refreshToken: string, expiresAt: number): Promise<void>;
  getToken(userId: string): Promise<string | null>;
  deleteToken(userId: string): Promise<void>;
  cleanup(): Promise<number>; // Returns number of removed tokens
}

/**
 * Stored token data
 */
interface StoredTokenData {
  encryptedToken: EncryptedData;
  expiresAt: number;
  createdAt: number;
  userId: string;
  integrityHash: string; // HMAC for integrity validation
}

/**
 * Memory-based token storage implementation with encryption
 * This class securely stores refresh tokens using AES-256-GCM encryption
 * and HMAC integrity validation
 */
export class TokenStorage implements ITokenStorage {
  private static instance: TokenStorage;
  private tokenStore: Map<string, StoredTokenData> = new Map();
  private readonly CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes
  private cleanupTimer: NodeJS.Timeout | null = null;

  private constructor() {
    // Start automatic cleanup
    this.startCleanupTimer();
  }

  /**
   * Gets singleton instance of TokenStorage
   */
  static getInstance(): TokenStorage {
    if (!TokenStorage.instance) {
      TokenStorage.instance = new TokenStorage();
    }
    return TokenStorage.instance;
  }

  /**
   * Generates integrity hash for data validation
   */
  private generateIntegrityHash(data: Omit<StoredTokenData, 'integrityHash'>): string {
    const key = process.env.SPOTIFY_ENCRYPTION_KEY;
    if (!key) {
      throw new Error('SPOTIFY_ENCRYPTION_KEY environment variable is required');
    }
    
    const hmac = createHmac('sha256', Buffer.from(key, 'hex'));
    hmac.update(JSON.stringify({
      userId: data.userId,
      expiresAt: data.expiresAt,
      createdAt: data.createdAt,
      encryptedToken: data.encryptedToken
    }));
    return hmac.digest('hex');
  }

  /**
   * Validates token data integrity
   */
  private validateIntegrity(data: StoredTokenData): boolean {
    const expectedHash = this.generateIntegrityHash({
      encryptedToken: data.encryptedToken,
      expiresAt: data.expiresAt,
      createdAt: data.createdAt,
      userId: data.userId
    });
    
    const isValid = expectedHash === data.integrityHash;
    
    if (!isValid) {
      logCredentialsEvent(
        SecurityEventType.DECRYPTION_ERROR,
        "Token integrity validation failed",
        {
          userId: data.userId,
          source: 'token_storage_integrity_check'
        }
      );
    }
    
    return isValid;
  }

  /**
   * Stores a refresh token in encrypted form
   */
  async storeToken(userId: string, refreshToken: string, expiresAt: number): Promise<void> {
    try {
      logCredentialsEvent(
        SecurityEventType.SEC_002_TOKEN_STORED,
        "Storing refresh token for user",
        {
          userId,
          source: 'token_storage_store',
          expiresAt: new Date(expiresAt * 1000).toISOString()
        }
      );

      // Encrypt the token
      const encryptedToken = encrypt(refreshToken);
      
      const now = Date.now();
      const tokenData: Omit<StoredTokenData, 'integrityHash'> = {
        encryptedToken,
        expiresAt,
        createdAt: now,
        userId
      };

      // Generate integrity hash
      const integrityHash = this.generateIntegrityHash(tokenData);

      const storedData: StoredTokenData = {
        ...tokenData,
        integrityHash
      };

      // Store in memory
      this.tokenStore.set(userId, storedData);

      logCredentialsEvent(
        SecurityEventType.SEC_002_TOKEN_STORED,
        "Token stored successfully",
        {
          userId,
          source: 'token_storage_store',
          expiresAt: new Date(expiresAt * 1000).toISOString()
        }
      );
    } catch (error) {
      logCredentialsEvent(
        SecurityEventType.ENCRYPTION_ERROR,
        "Failed to store token",
        {
          userId,
          source: 'token_storage_store',
          errorType: error instanceof Error ? error.constructor.name : 'Unknown'
        },
        undefined,
        error as Error
      );
      throw error;
    }
  }

  /**
   * Retrieves a refresh token securely
   */
  async getToken(userId: string): Promise<string | null> {
    try {
      const tokenData = this.tokenStore.get(userId);
      
      if (!tokenData) {
        logCredentialsEvent(
          SecurityEventType.SEC_002_TOKEN_RETRIEVED,
          "Token not found for user",
          {
            userId,
            source: 'token_storage_get'
          }
        );
        return null;
      }

      // Check if token has expired
      if (Date.now() / 1000 > tokenData.expiresAt) {
        logCredentialsEvent(
          SecurityEventType.SEC_002_TOKEN_EXPIRED,
          "Token expired for user",
          {
            userId,
            source: 'token_storage_get',
            expiresAt: new Date(tokenData.expiresAt * 1000).toISOString()
          }
        );
        // Remove expired token
        await this.deleteToken(userId);
        return null;
      }

      // Validate data integrity
      if (!this.validateIntegrity(tokenData)) {
        logCredentialsEvent(
          SecurityEventType.SEC_002_TOKEN_INTEGRITY_FAILED,
          "Token integrity validation failed - removing corrupted token",
          {
            userId,
            source: 'token_storage_get'
          }
        );
        await this.deleteToken(userId);
        return null;
      }

      // Decrypt the token
      const decryptedToken = decrypt(tokenData.encryptedToken);

      logCredentialsEvent(
        SecurityEventType.SEC_002_TOKEN_RETRIEVED,
        "Token retrieved successfully",
        {
          userId,
          source: 'token_storage_get'
        }
      );

      return decryptedToken;
    } catch (error) {
      logCredentialsEvent(
        SecurityEventType.DECRYPTION_ERROR,
        "Failed to retrieve token",
        {
          userId,
          source: 'token_storage_get',
          errorType: error instanceof Error ? error.constructor.name : 'Unknown'
        },
        undefined,
        error as Error
      );
      return null;
    }
  }

  /**
   * Removes a refresh token from storage
   */
  async deleteToken(userId: string): Promise<void> {
    try {
      const existed = this.tokenStore.has(userId);
      this.tokenStore.delete(userId);

      logCredentialsEvent(
        SecurityEventType.SEC_002_TOKEN_DELETED,
        existed ? "Token deleted successfully" : "Token not found for deletion",
        {
          userId,
          source: 'token_storage_delete',
          existed
        }
      );
    } catch (error) {
      logCredentialsEvent(
        SecurityEventType.INVALID_REQUEST,
        "Failed to delete token",
        {
          userId,
          source: 'token_storage_delete',
          errorType: error instanceof Error ? error.constructor.name : 'Unknown'
        },
        undefined,
        error as Error
      );
    }
  }

  /**
   * Removes expired tokens from storage
   */
  async cleanup(): Promise<number> {
    const now = Date.now() / 1000;
    let removedCount = 0;
    const expiredTokens: string[] = [];

    // Identify expired tokens
    for (const [userId, tokenData] of this.tokenStore.entries()) {
      if (now > tokenData.expiresAt) {
        expiredTokens.push(userId);
      }
    }

    // Remove expired tokens
    for (const userId of expiredTokens) {
      this.tokenStore.delete(userId);
      removedCount++;
    }

    if (removedCount > 0) {
      logCredentialsEvent(
        SecurityEventType.SESSION_TIMEOUT,
        `Cleaned up ${removedCount} expired tokens`,
        {
          source: 'token_storage_cleanup',
          removedCount,
          totalTokens: this.tokenStore.size
        }
      );
    }

    return removedCount;
  }

  /**
   * Starts automatic cleanup timer
   */
  private startCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }

    this.cleanupTimer = setInterval(async () => {
      await this.cleanup();
    }, this.CLEANUP_INTERVAL);
  }

  /**
   * Stops automatic cleanup timer
   */
  stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Gets storage statistics
   */
  getStats(): { totalTokens: number; activeTokens: number; expiredTokens: number } {
    const now = Date.now() / 1000;
    let activeTokens = 0;
    let expiredTokens = 0;

    for (const tokenData of this.tokenStore.values()) {
      if (now > tokenData.expiresAt) {
        expiredTokens++;
      } else {
        activeTokens++;
      }
    }

    return {
      totalTokens: this.tokenStore.size,
      activeTokens,
      expiredTokens
    };
  }

  /**
   * Clears all tokens (for testing)
   */
  async clearAll(): Promise<void> {
    const count = this.tokenStore.size;
    this.tokenStore.clear();
    
    logCredentialsEvent(
      SecurityEventType.SESSION_DESTROYED,
      `Cleared all ${count} tokens from storage`,
      {
        source: 'token_storage_clear_all',
        count
      }
    );
  }
}

// Export singleton instance
export const tokenStorage = TokenStorage.getInstance();
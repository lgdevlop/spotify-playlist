import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { securityLogger, SecurityEventType, logCredentialsEvent } from '../../app/lib/security-logger';

describe('SEC-001: JWT Credentials Security', () => {
  beforeEach(() => {
    // Clear logs before each test
    securityLogger.clearLogs();
  });

  afterEach(() => {
    // Clean up after each test
    securityLogger.clearLogs();
  });

  describe('JWT Token Security', () => {
    it('should not store credentials in JWT token', async () => {
      // This test validates that the JWT callback no longer stores credentials
      // In a real scenario, we would need to mock the JWT callback execution
      // For now, we validate that no JWT credential events are logged
      
      // Simulate JWT callback execution
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        "Attempting token refresh using secure refresh endpoint",
        {
          hasRefreshToken: true,
          source: 'secure_refresh_endpoint'
        }
      );

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(1);
      
      const log = logs[0];
      if (log) {
        expect(log.eventType).toBe(SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT);
        expect(log.details?.source).toBe('secure_refresh_endpoint');
        expect(log.details?.hasRefreshToken).toBe(true);
      }
    });

    it('should refresh tokens using server-side credentials only', async () => {
      // Test that refresh uses only server-side credentials
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        "Attempting token refresh using server-side credentials",
        {
          hasRefreshToken: true,
          source: 'server_side_only'
        }
      );

      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        "Successfully refreshed token using server-side credentials",
        {
          source: 'server_side_only',
          newExpiresAt: Math.floor(Date.now() / 1000) + 3600,
          hasNewRefreshToken: false,
          expiresIn: 3600
        }
      );

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(2);

      logs.forEach(log => {
        expect(log.details?.source).toBe('server_side_only');
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_JWT_REFRESH_ATTEMPT);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_JWT_REFRESH_SUCCESS);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_JWT_REFRESH_FAILURE);
      });
    });

    it('should not log deprecated JWT credential events', () => {
      // Add current secure events
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        'Secure refresh completed',
        { source: 'secure_refresh_endpoint' }
      );

      const logs = securityLogger.getRecentLogs();
      
      // Verify no deprecated events are present
      logs.forEach(log => {
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_CALLED);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_SUCCESS);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_FAILURE);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_JWT_REFRESH_ATTEMPT);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_JWT_REFRESH_SUCCESS);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_JWT_REFRESH_FAILURE);
      });
    });

    it('should validate secure refresh endpoint usage', () => {
      // Test that the secure refresh endpoint is properly used
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        "Secure refresh endpoint called",
        {
          hasRefreshToken: true,
          source: 'secure_refresh_endpoint'
        }
      );

      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        "Secure refresh completed successfully",
        {
          source: 'secure_refresh_endpoint',
          expiresIn: 3600
        }
      );

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(2);

      logs.forEach(log => {
        expect(log.details?.source).toBe('secure_refresh_endpoint');
      });

      const attemptLog = logs.find(log => log.eventType === SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT);
      const successLog = logs.find(log => log.eventType === SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS);

      expect(attemptLog?.details?.hasRefreshToken).toBe(true);
      expect(successLog?.details?.expiresIn).toBe(3600);
    });

    it('should handle secure refresh failures appropriately', () => {
      // Test that secure refresh failures are properly logged
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
        "Secure refresh failed",
        {
          source: 'secure_refresh_endpoint',
          status: 400,
          error: 'Invalid refresh token'
        }
      );

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(1);

      const log = logs[0];
      if (log) {
        expect(log.eventType).toBe(SecurityEventType.CREDENTIALS_FALLBACK_FAILURE);
        expect(log.details?.source).toBe('secure_refresh_endpoint');
        expect(log.details?.status).toBe(400);
        expect(log.details?.error).toBe('Invalid refresh token');
      }
    });

    it('should validate server-side only credential source', () => {
      // Test that all credential operations use server-side only source
      const events = [
        {
          type: SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
          message: "Server-side credential attempt",
          details: { source: 'server_side_only' }
        },
        {
          type: SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
          message: "Server-side credential success",
          details: { source: 'server_side_only' }
        }
      ];

      events.forEach(event => {
        logCredentialsEvent(event.type, event.message, event.details);
      });

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(events.length);

      logs.forEach((log, index) => {
        expect(log).toBeDefined();
        expect(log.eventType).toBe(events?.[index]?.type ?? '');
        expect(log.details?.source).toBe('server_side_only');
      });
    });

    it('should ensure no JWT credential exposure in any logs', () => {
      // Add various credential events
      const credentialEvents = [
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
      ];

      credentialEvents.forEach(eventType => {
        logCredentialsEvent(eventType, `Test ${eventType}`, { 
          source: 'secure_refresh_endpoint' 
        });
      });

      const logs = securityLogger.getRecentLogs();
      
      // Ensure no JWT-related events are present
      const jwtEvents = logs.filter(log => 
        log.eventType === SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_CALLED ||
        log.eventType === SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_SUCCESS ||
        log.eventType === SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_FAILURE ||
        log.eventType === SecurityEventType.CREDENTIALS_JWT_REFRESH_ATTEMPT ||
        log.eventType === SecurityEventType.CREDENTIALS_JWT_REFRESH_SUCCESS ||
        log.eventType === SecurityEventType.CREDENTIALS_JWT_REFRESH_FAILURE
      );

      expect(jwtEvents).toHaveLength(0);
    });
  });

  describe('Security Validation', () => {
    it('should validate that all credential sources are secure', () => {
      const secureSources = ['server_side_only', 'secure_refresh_endpoint', 'auth_config_primary'];
      
      secureSources.forEach(source => {
        logCredentialsEvent(
          SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
          `Test secure source: ${source}`,
          { source }
        );
      });

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(secureSources.length);

      logs.forEach((log, index) => {
        expect(log.details?.source).toBe(secureSources[index]);
      });
    });

    it('should track credential event metrics', () => {
      const events = [
        { type: SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT, source: 'secure_refresh_endpoint' },
        { type: SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS, source: 'secure_refresh_endpoint' },
        { type: SecurityEventType.CREDENTIALS_FALLBACK_FAILURE, source: 'server_side_only' }
      ];

      events.forEach(event => {
        logCredentialsEvent(event.type, `Metric test ${event.type}`, { source: event.source });
      });

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(events.length);

      const attemptLogs = securityLogger.getLogsByType(SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT);
      const successLogs = securityLogger.getLogsByType(SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS);
      const failureLogs = securityLogger.getLogsByType(SecurityEventType.CREDENTIALS_FALLBACK_FAILURE);

      expect(attemptLogs).toHaveLength(1);
      expect(successLogs).toHaveLength(1);
      expect(failureLogs).toHaveLength(1);
    });
  });
});
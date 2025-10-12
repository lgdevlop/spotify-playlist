import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { securityLogger, SecurityEventType, logCredentialsEvent } from '../../app/lib/security-logger';

describe('Credentials Tracking Logs', () => {
  beforeEach(() => {
    // Clear logs before each test
    securityLogger.clearLogs();
  });

  afterEach(() => {
    // Clean up after each test
    securityLogger.clearLogs();
  });

  describe('logCredentialsEvent', () => {
    it('should log credential events with proper structure', () => {
      const message = 'Test credential event';
      const details = {
        source: 'test',
        hasClientId: true,
        hasClientSecret: true
      };

      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_CALLED,
        message,
        details
      );

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(1);
      
      const log = logs[0];
      if (log) {
        expect(log.eventType).toBe(SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_CALLED);
        expect(log.details?.message).toBe(message);
        expect(log.details?.tracking_source).toBe('credentials_tracking');
        expect(log.details?.source).toBe('test');
        expect(log.details?.hasClientId).toBe(true);
        expect(log.details?.hasClientSecret).toBe(true);
      }
    });

    it('should sanitize sensitive data in credential logs', () => {
      const message = 'Test with sensitive data';
      const details = {
        clientSecret: 'super-secret-key',
        access_token: 'token123',
        normalField: 'normal-value'
      };

      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_JWT_REFRESH_SUCCESS,
        message,
        details
      );

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(1);
      
      const log = logs[0];
      if (log) {
        expect(log.details?.clientSecret).toBe('[REDACTED]');
        expect(log.details?.access_token).toBe('[REDACTED]');
        expect(log.details?.normalField).toBe('normal-value');
      }
    });

    it('should include error information when provided', () => {
      const message = 'Test error event';
      const error = new Error('Test error message');
      const details = { source: 'test' };

      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
        message,
        details,
        undefined,
        error
      );

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(1);
      
      const log = logs[0];
      if (log) {
        expect(log.error).toBe('Test error message');
        expect(log.details?.message).toBe(message);
      }
    });
  });

  describe('Credential Event Types', () => {
    it('should track all credential-related event types', () => {
      const credentialEvents = [
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
      ];

      credentialEvents.forEach(eventType => {
        logCredentialsEvent(eventType, `Test ${eventType}`, { source: 'test' });
      });

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(credentialEvents.length);

      credentialEvents.forEach((eventType, index) => {
        const log = logs[index];
        if (log) {
          expect(log.eventType).toBe(eventType);
          expect(log.details?.tracking_source).toBe('credentials_tracking');
          expect(log.details?.source).toBe('test');
        }
      });
    });

    it('should track secure refresh endpoint events', () => {
      const secureRefreshEvents = [
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
      ];

      secureRefreshEvents.forEach(eventType => {
        logCredentialsEvent(eventType, `Test secure refresh ${eventType}`, {
          source: 'secure_refresh_endpoint',
          hasRefreshToken: true
        });
      });

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(secureRefreshEvents.length);

      secureRefreshEvents.forEach((eventType, index) => {
        const log = logs[index];
        if (log) {
          expect(log.eventType).toBe(eventType);
          expect(log.details?.source).toBe('secure_refresh_endpoint');
          expect(log.details?.hasRefreshToken).toBe(true);
        }
      });
    });

    it('should track server-side only credential events', () => {
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        "Test server-side only refresh",
        {
          source: 'server_side_only',
          hasRefreshToken: true
        }
      );

      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        "Test server-side only success",
        {
          source: 'server_side_only',
          newExpiresAt: Math.floor(Date.now() / 1000) + 3600
        }
      );

      const logs = securityLogger.getRecentLogs();
      expect(logs).toHaveLength(2);

      logs.forEach(log => {
        expect(log.details?.source).toBe('server_side_only');
      });
    });
  });

  describe('Log Filtering', () => {
    it('should filter logs by credential event type', () => {
      // Add some credential logs
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        'Server-side refresh success',
        { source: 'server_side_only' }
      );
      
      // Add some non-credential logs
      securityLogger.log(
        SecurityEventType.AUTH_SUCCESS,
        undefined,
        { message: 'Regular auth success' }
      );

      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        'Secure refresh success',
        { source: 'secure_refresh_endpoint' }
      );

      // Get all credential-related logs
      const credentialEvents = [
        SecurityEventType.CREDENTIALS_FALLBACK_ATTEMPT,
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        SecurityEventType.CREDENTIALS_FALLBACK_FAILURE,
      ];

      let credentialLogCount = 0;
      credentialEvents.forEach(eventType => {
        const logs = securityLogger.getLogsByType(eventType);
        credentialLogCount += logs.length;
      });

      expect(credentialLogCount).toBe(2); // We added 2 credential logs
    });

    it('should not contain deprecated JWT credential events', () => {
      // Add current credential events
      logCredentialsEvent(
        SecurityEventType.CREDENTIALS_FALLBACK_SUCCESS,
        'Current secure refresh',
        { source: 'secure_refresh_endpoint' }
      );

      const logs = securityLogger.getRecentLogs();
      
      // Should only contain current events
      logs.forEach(log => {
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_CALLED);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_SUCCESS);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_FROM_SESSION_TOKEN_FAILURE);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_JWT_REFRESH_ATTEMPT);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_JWT_REFRESH_SUCCESS);
        expect(log.eventType).not.toBe(SecurityEventType.CREDENTIALS_JWT_REFRESH_FAILURE);
      });
    });
  });
});
import type { NextApiRequest } from 'next';
import type { NextRequest } from 'next/server';
import type { SecurityLogEntry } from '../../types';

export enum SecurityEventType {
  SESSION_CREATED = 'SESSION_CREATED',
  SESSION_DESTROYED = 'SESSION_DESTROYED',
  CONFIG_STORED = 'CONFIG_STORED',
  CONFIG_RETRIEVED = 'CONFIG_RETRIEVED',
  AUTH_ATTEMPT = 'AUTH_ATTEMPT',
  AUTH_SUCCESS = 'AUTH_SUCCESS',
  AUTH_FAILURE = 'AUTH_FAILURE',
  ENCRYPTION_ERROR = 'ENCRYPTION_ERROR',
  DECRYPTION_ERROR = 'DECRYPTION_ERROR',
  INVALID_REQUEST = 'INVALID_REQUEST',
  SESSION_TIMEOUT = 'SESSION_TIMEOUT',
  SESSION_INACTIVITY = 'SESSION_INACTIVITY',
  JWT_CALLBACK_TRIGGERED = 'JWT_CALLBACK_TRIGGERED',
  JWT_CALLBACK_INITIAL_SETUP = 'JWT_CALLBACK_INITIAL_SETUP',
  JWT_CALLBACK_TOKEN_REFRESH = 'JWT_CALLBACK_TOKEN_REFRESH',
  JWT_CALLBACK_COMPLETED = 'JWT_CALLBACK_COMPLETED',
  AUTH_DEBUG = 'AUTH_DEBUG',
  // Credential tracking events
  CREDENTIALS_FROM_SESSION_TOKEN_CALLED = 'CREDENTIALS_FROM_SESSION_TOKEN_CALLED',
  CREDENTIALS_FROM_SESSION_TOKEN_SUCCESS = 'CREDENTIALS_FROM_SESSION_TOKEN_SUCCESS',
  CREDENTIALS_FROM_SESSION_TOKEN_FAILURE = 'CREDENTIALS_FROM_SESSION_TOKEN_FAILURE',
  CREDENTIALS_JWT_REFRESH_ATTEMPT = 'CREDENTIALS_JWT_REFRESH_ATTEMPT',
  CREDENTIALS_JWT_REFRESH_SUCCESS = 'CREDENTIALS_JWT_REFRESH_SUCCESS',
  CREDENTIALS_JWT_REFRESH_FAILURE = 'CREDENTIALS_JWT_REFRESH_FAILURE',
  CREDENTIALS_FALLBACK_ATTEMPT = 'CREDENTIALS_FALLBACK_ATTEMPT',
  CREDENTIALS_FALLBACK_SUCCESS = 'CREDENTIALS_FALLBACK_SUCCESS',
  CREDENTIALS_FALLBACK_FAILURE = 'CREDENTIALS_FALLBACK_FAILURE',
  // SEC-002 specific events
  SEC_002_TOKEN_STORED = 'SEC_002_TOKEN_STORED',
  SEC_002_TOKEN_RETRIEVED = 'SEC_002_TOKEN_RETRIEVED',
  SEC_002_TOKEN_REFRESHED = 'SEC_002_TOKEN_REFRESHED',
  SEC_002_TOKEN_DELETED = 'SEC_002_TOKEN_DELETED',
  SEC_002_TOKEN_EXPIRED = 'SEC_002_TOKEN_EXPIRED',
  SEC_002_TOKEN_INTEGRITY_FAILED = 'SEC_002_TOKEN_INTEGRITY_FAILED',
  SEC_002_RATE_LIMIT_EXCEEDED = 'SEC_002_RATE_LIMIT_EXCEEDED',
  SEC_002_REFRESH_ATTEMPT = 'SEC_002_REFRESH_ATTEMPT',
  SEC_002_REFRESH_SUCCESS = 'SEC_002_REFRESH_SUCCESS',
  SEC_002_REFRESH_FAILURE = 'SEC_002_REFRESH_FAILURE',
}

/**
 * Sanitizes sensitive data from log entries
 */
function sanitizeLogData(data: unknown): unknown {
  if (typeof data !== 'object' || data === null) {
    return data;
  }

  const sanitized = { ...(data as Record<string, unknown>) };

  // Remove or mask sensitive fields
  const sensitiveFields = [
    'clientSecret',
    'client_secret',
    'password',
    'token',
    'access_token',
    'accessToken', // Add camelCase version
    'refresh_token',
    'refreshToken', // Add camelCase version
    'authorization',
    'cookie',
    'session',
  ];

  for (const field of sensitiveFields) {
    if (field in sanitized) {
      sanitized[field] = '[REDACTED]';
    }
  }

  // Recursively sanitize nested objects
  for (const key in sanitized) {
    if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
      sanitized[key] = sanitizeLogData(sanitized[key]);
    }
  }

  return sanitized;
}

/**
 * Extracts client information from request
 */
function extractClientInfo(req: NextApiRequest | NextRequest): { userAgent?: string; ip?: string } {
  // ✅ SECURITY FIX: Handle cases where req.headers is undefined
  if (!req || !req.headers) {
    return { userAgent: undefined, ip: undefined };
  }

  const headers = req.headers as unknown as Record<string, string | string[]> & { get?: (key: string) => string | null };

  const getHeaderValue = (key: string): string | undefined => {
    if (headers && headers.get) {
      return headers.get(key) || undefined;
    }
    if (headers) {
      const value = headers[key];
      return Array.isArray(value) ? value[0] : value;
    }
    return undefined;
  };

  return {
    userAgent: getHeaderValue('user-agent'),
    ip: getHeaderValue('x-forwarded-for') || getHeaderValue('x-real-ip') ||
        (req as unknown as { connection?: { remoteAddress?: string }; socket?: { remoteAddress?: string } }).connection?.remoteAddress ||
        (req as unknown as { connection?: { remoteAddress?: string }; socket?: { remoteAddress?: string } }).socket?.remoteAddress,
  };
}

/**
 * Logs security events securely
 */
export class SecurityLogger {
  private static instance: SecurityLogger;
  private logs: SecurityLogEntry[] = [];
  private readonly maxLogs = 1000; // Keep last 1000 entries in memory

  private constructor() {}

  static getInstance(): SecurityLogger {
    if (!SecurityLogger.instance) {
      SecurityLogger.instance = new SecurityLogger();
    }
    return SecurityLogger.instance;
  }

  /**
   * Logs a security event
   */
  log(
    eventType: SecurityEventType,
    req?: NextApiRequest | NextRequest,
    details?: Record<string, unknown>,
    error?: Error | string
  ): void {
    const entry: SecurityLogEntry = {
      timestamp: Date.now(),
      eventType,
      ...extractClientInfo(req || ({} as NextApiRequest)),
      details: details ? sanitizeLogData(details) as Record<string, unknown> : undefined,
      error: error ? (typeof error === 'string' ? error : error.message) : undefined,
    };

    this.logs.push(entry);

    // Keep only the last maxLogs entries
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }

    // In production, you might want to send to external logging service
    console.log(`[SECURITY] ${eventType}`, {
      ...entry,
      timestamp: new Date(entry.timestamp).toISOString(),
    });
  }

  /**
   * Gets recent security logs
   */
  getRecentLogs(limit = 100): SecurityLogEntry[] {
    return this.logs.slice(-limit);
  }

  /**
   * Gets logs by event type
   */
  getLogsByType(eventType: SecurityEventType, limit = 50): SecurityLogEntry[] {
    return this.logs
      .filter(log => log.eventType === eventType)
      .slice(-limit);
  }

  /**
   * Clears all logs
   */
  clearLogs(): void {
    this.logs = [];
  }
}

// Export singleton instance
export const securityLogger = SecurityLogger.getInstance();

// Convenience functions
export const logSecurityEvent = (
  eventType: SecurityEventType,
  req?: NextApiRequest | NextRequest,
  details?: Record<string, unknown>,
  error?: Error | string
) => securityLogger.log(eventType, req, details, error);

export const logError = (
  message: string,
  error?: Error | string,
  req?: NextApiRequest | NextRequest,
  details?: Record<string, unknown>
): void => {
  const sanitizedError = typeof error === 'string' ? error : error instanceof Error ? error.message : 'Unknown error';
  logSecurityEvent(
    SecurityEventType.INVALID_REQUEST,
    req,
    { message, ...(details || {}) },
    sanitizedError
  );
};

/**
 * Logs authentication debug information
 */
export const logAuthDebug = (
  message: string,
  eventType: SecurityEventType = SecurityEventType.AUTH_DEBUG,
  details?: Record<string, unknown>,
  req?: NextApiRequest | NextRequest
): void => {
  logSecurityEvent(
    eventType,
    req,
    { message, ...(details || {}) }
  );
};

/**
 * Logs JWT callback events with appropriate security context
 */
export const logJwtCallback = (
  stage: 'triggered' | 'initial_setup' | 'token_refresh' | 'completed',
  message: string,
  details?: Record<string, unknown>
): void => {
  const eventTypes = {
    triggered: SecurityEventType.JWT_CALLBACK_TRIGGERED,
    initial_setup: SecurityEventType.JWT_CALLBACK_INITIAL_SETUP,
    token_refresh: SecurityEventType.JWT_CALLBACK_TOKEN_REFRESH,
    completed: SecurityEventType.JWT_CALLBACK_COMPLETED,
  };

  logSecurityEvent(
    eventTypes[stage],
    undefined,
    { message, ...(details || {}) }
  );
};

/**
 * Logs credential-related events with structured data
 */
export const logCredentialsEvent = (
  eventType: SecurityEventType,
  message: string,
  details?: Record<string, unknown>,
  req?: NextApiRequest | NextRequest,
  error?: Error | string
): void => {
  logSecurityEvent(
    eventType,
    req,
    {
      message,
      tracking_source: 'credentials_tracking',
      ...(details || {})
    },
    error
  );
};
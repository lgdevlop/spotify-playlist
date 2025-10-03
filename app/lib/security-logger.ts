import type { NextApiRequest } from 'next';
import type { NextRequest } from 'next/server';

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
}

export interface SecurityLogEntry {
  timestamp: number;
  eventType: SecurityEventType;
  userAgent?: string;
  ip?: string;
  sessionId?: string;
  details?: Record<string, any>;
  error?: string;
}

/**
 * Sanitizes sensitive data from log entries
 */
function sanitizeLogData(data: any): any {
  if (typeof data !== 'object' || data === null) {
    return data;
  }

  const sanitized = { ...data };

  // Remove or mask sensitive fields
  const sensitiveFields = [
    'clientSecret',
    'client_secret',
    'password',
    'token',
    'access_token',
    'refresh_token',
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
  const headers = req.headers as any;

  return {
    userAgent: headers.get ? headers.get('user-agent') : headers['user-agent'],
    ip: headers.get ? headers.get('x-forwarded-for') || headers.get('x-real-ip') :
        headers['x-forwarded-for'] || headers['x-real-ip'] ||
        (req as any).connection?.remoteAddress ||
        (req as any).socket?.remoteAddress,
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
    details?: Record<string, any>,
    error?: Error | string
  ): void {
    const entry: SecurityLogEntry = {
      timestamp: Date.now(),
      eventType,
      ...extractClientInfo(req || ({} as NextApiRequest)),
      details: details ? sanitizeLogData(details) : undefined,
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
  details?: Record<string, any>,
  error?: Error | string
) => securityLogger.log(eventType, req, details, error);
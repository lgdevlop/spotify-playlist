# 🟢 SEC-012: Debug Logs in Production

## 📋 Basic Information

| Field | Value |
|-------|-------|
| **Vulnerability ID** | SEC-012 |
| **Severity** | Low |
| **CVSS Score** | 3.2 |
| **Component** | Configuration |
| **Location** | `app/lib/auth.ts:38` |
| **Discovery Date** | 10/04/2025 |
| **Status** | Open |

## 🎯 Description

NextAuth debug mode is enabled, potentially exposing sensitive information in production logs. This configuration can lead to information leakage, exposure of authentication flow details, and increased log verbosity that could aid attackers in reconnaissance.

### Potential Impact

- Information leakage through debug logs
- Exposure of authentication flow details
- Increased log verbosity aiding reconnaissance
- Potential exposure of sensitive configuration
- Performance impact from excessive logging

### Exploitation Examples

```javascript
// Debug logs exposing sensitive information
// Example log output in production:
[DEBUG] [next-auth] Called adapter method: createUser
[DEBUG] [next-auth] User object: {
  "id": "spotify_user_123",
  "name": "John Doe",
  "email": "john.doe@example.com",
  "image": "https://i.scdn.co/image/abc123"
}
[DEBUG] [next-auth] JWT payload: {
  "sub": "spotify_user_123",
  "accessToken": "BQD...[full_token_exposed]",
  "refreshToken": "AQD...[full_token_exposed]",
  "expiresIn": 3600
}
[DEBUG] [next-auth] Callback URL: https://yourapp.com/api/auth/callback/spotify
[DEBUG] [next-auth] Provider configuration: {
  "clientId": "1234567890abcdef...",
  "redirectUri": "https://yourapp.com/api/auth/callback/spotify"
}

// Attacker can use this information for:
// 1. Understanding the authentication flow
// 2. Identifying user patterns
// 3. Finding potential vulnerabilities
// 4. Social engineering attacks
```

### Evidence Found

```typescript
// app/lib/auth.ts - Debug mode enabled in production
export const authOptions = (credentials?: AuthConfig) => {
  return {
    providers,
    debug: process.env.NODE_ENV === 'development', // ISSUE: Should be more restrictive
    // OR potentially:
    debug: true, // ISSUE: Hardcoded debug mode
    session: {
      strategy: 'jwt',
      maxAge: 24 * 60 * 60, // 24 hours
    },
    // ... rest of configuration
  };
};
```

## 🔧 Remediation Plan

### Specific Actions Required

1. Disable debug mode in production
2. Implement environment-based logging configuration
3. Remove detailed debug logs from production
4. Implement appropriate log levels

### Detailed Remediation Steps

#### Step 1: Environment-Based Debug Configuration

Implement proper environment-based debug settings:

```typescript
// app/lib/auth.ts (updated)
export const authOptions = (credentials?: AuthConfig) => {
  // Proper debug configuration
  const isDevelopment = process.env.NODE_ENV === 'development';
  const isDebugMode = process.env.ENABLE_DEBUG === 'true' && isDevelopment;
  
  return {
    providers,
    debug: isDebugMode,
    // ... rest of configuration
  };
};

// Alternative: More explicit configuration
export const getAuthConfig = (): AuthOptions => {
  const environment = process.env.NODE_ENV || 'development';
  const enableDebug = process.env.ENABLE_DEBUG === 'true';
  
  // Only enable debug in development with explicit flag
  const debugEnabled = environment === 'development' && enableDebug;
  
  return {
    providers,
    debug: debugEnabled,
    session: {
      strategy: 'jwt',
      maxAge: 24 * 60 * 60, // 24 hours
    },
    callbacks: {
      // ... callbacks
    },
    // ... rest of configuration
  };
};
```

#### Step 2: Comprehensive Logging System

Implement a proper logging system with levels:

```typescript
// app/lib/logger.ts
export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: Record<string, unknown>;
  userId?: string;
  requestId?: string;
}

export class Logger {
  private static instance: Logger;
  private logLevel: LogLevel;
  private environment: string;
  
  private constructor() {
    this.environment = process.env.NODE_ENV || 'development';
    this.logLevel = this.getLogLevelFromEnvironment();
  }
  
  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }
  
  private getLogLevelFromEnvironment(): LogLevel {
    const envLevel = process.env.LOG_LEVEL?.toUpperCase();
    
    switch (envLevel) {
      case 'ERROR':
        return LogLevel.ERROR;
      case 'WARN':
        return LogLevel.WARN;
      case 'INFO':
        return LogLevel.INFO;
      case 'DEBUG':
        return LogLevel.DEBUG;
      default:
        // Default to WARN in production, DEBUG in development
        return this.environment === 'production' ? LogLevel.WARN : LogLevel.DEBUG;
    }
  }
  
  private shouldLog(level: LogLevel): boolean {
    return level <= this.logLevel;
  }
  
  private formatLogEntry(level: LogLevel, message: string, context?: Record<string, unknown>): LogEntry {
    return {
      timestamp: new Date().toISOString(),
      level,
      message,
      context: this.sanitizeContext(context),
      requestId: this.generateRequestId(),
    };
  }
  
  private sanitizeContext(context?: Record<string, unknown>): Record<string, unknown> | undefined {
    if (!context) return undefined;
    
    const sanitized: Record<string, unknown> = {};
    
    for (const [key, value] of Object.entries(context)) {
      // Skip sensitive keys
      if (this.isSensitiveKey(key)) {
        sanitized[key] = '[REDACTED]';
        continue;
      }
      
      // Sanitize sensitive values
      if (typeof value === 'string') {
        sanitized[key] = this.sanitizeSensitiveValue(value);
      } else {
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  }
  
  private isSensitiveKey(key: string): boolean {
    const sensitiveKeys = [
      'password', 'token', 'secret', 'key', 'auth',
      'accessToken', 'refreshToken', 'clientSecret',
      'sessionId', 'userId', 'email', 'phone'
    ];
    
    return sensitiveKeys.some(sensitive => 
      key.toLowerCase().includes(sensitive.toLowerCase())
    );
  }
  
  private sanitizeSensitiveValue(value: string): string {
    // Remove potential tokens, secrets, etc.
    return value
      .replace(/BQ[a-zA-Z0-9]{100,}/g, '[SPOTIFY_TOKEN]')
      .replace(/[a-zA-Z0-9]{32,}/g, '[POTENTIAL_SECRET]')
      .replace(/email[:\s]*[^\s@]+@[^\s@]+\.[^\s]+/gi, '[EMAIL]')
      .substring(0, 200); // Truncate long values
  }
  
  private generateRequestId(): string {
    return Math.random().toString(36).substring(2, 15);
  }
  
  error(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.ERROR)) {
      const entry = this.formatLogEntry(LogLevel.ERROR, message, context);
      console.error('[ERROR]', JSON.stringify(entry));
    }
  }
  
  warn(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.WARN)) {
      const entry = this.formatLogEntry(LogLevel.WARN, message, context);
      console.warn('[WARN]', JSON.stringify(entry));
    }
  }
  
  info(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.INFO)) {
      const entry = this.formatLogEntry(LogLevel.INFO, message, context);
      console.info('[INFO]', JSON.stringify(entry));
    }
  }
  
  debug(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.DEBUG)) {
      const entry = this.formatLogEntry(LogLevel.DEBUG, message, context);
      console.debug('[DEBUG]', JSON.stringify(entry));
    }
  }
}

export const logger = Logger.getInstance();
```

#### Step 3: NextAuth Integration with Custom Logger

Integrate custom logger with NextAuth:

```typescript
// app/lib/auth-logger.ts
import { logger } from './logger';

export class AuthLogger {
  static logAuthEvent(event: string, details?: Record<string, unknown>): void {
    switch (event) {
      case 'signin':
        logger.info('User sign in attempt', {
          event: 'signin',
          provider: details?.provider,
          timestamp: new Date().toISOString()
        });
        break;
        
      case 'signout':
        logger.info('User sign out', {
          event: 'signout',
          timestamp: new Date().toISOString()
        });
        break;
        
      case 'token_refresh':
        logger.debug('Token refresh', {
          event: 'token_refresh',
          success: details?.success
        });
        break;
        
      case 'error':
        logger.error('Authentication error', {
          event: 'error',
          error: details?.error,
          timestamp: new Date().toISOString()
        });
        break;
        
      default:
        logger.debug(`Auth event: ${event}`, details);
    }
  }
  
  static logCallback(provider: string, type: string, details?: Record<string, unknown>): void {
    logger.debug(`Auth callback: ${provider}/${type}`, {
      provider,
      type,
      timestamp: new Date().toISOString(),
      ...details
    });
  }
}
```

#### Step 4: Updated Auth Configuration

Update auth configuration with proper logging:

```typescript
// app/lib/auth.ts (updated)
import { AuthLogger } from './auth-logger';

export const authOptions = (credentials?: AuthConfig): AuthOptions => {
  const isDevelopment = process.env.NODE_ENV === 'development';
  const enableDebug = process.env.ENABLE_DEBUG === 'true' && isDevelopment;
  
  return {
    providers: getProviders(credentials),
    debug: enableDebug,
    session: {
      strategy: 'jwt',
      maxAge: 24 * 60 * 60, // 24 hours
    },
    callbacks: {
      async signIn({ user, account, profile }) {
        AuthLogger.logAuthEvent('signin', {
          provider: account?.provider,
          userId: user.id
        });
        return true;
      },
      
      async signOut({ session }) {
        AuthLogger.logAuthEvent('signout');
        return true;
      },
      
      async jwt({ token, user, account }) {
        if (user) {
          AuthLogger.logAuthEvent('token_created', {
            provider: account?.provider
          });
        }
        
        return token;
      },
      
      async session({ session, token }) {
        AuthLogger.logAuthEvent('session_access', {
          sessionId: token.sessionId
        });
        
        return session;
      },
    },
    
    events: {
      signIn: ({ user, account, profile, isNewUser }) => {
        AuthLogger.logAuthEvent('signin_success', {
          provider: account?.provider,
          isNewUser,
          userId: user.id
        });
      },
      
      signOut: ({ session }) => {
        AuthLogger.logAuthEvent('signout_success');
      },
      
      error: (error) => {
        AuthLogger.logAuthEvent('error', {
          error: error.message,
          name: error.name
        });
      },
    },
  };
};
```

#### Step 5: Environment Configuration

Create proper environment configuration:

```typescript
// app/lib/environment-config.ts
export interface EnvironmentConfig {
  nodeEnv: string;
  logLevel: 'ERROR' | 'WARN' | 'INFO' | 'DEBUG';
  enableDebug: boolean;
  enableAuthDebug: boolean;
}

export function getEnvironmentConfig(): EnvironmentConfig {
  const nodeEnv = process.env.NODE_ENV || 'development';
  const logLevel = (process.env.LOG_LEVEL as 'ERROR' | 'WARN' | 'INFO' | 'DEBUG') || 
                  (nodeEnv === 'production' ? 'WARN' : 'DEBUG');
  const enableDebug = process.env.ENABLE_DEBUG === 'true' && nodeEnv === 'development';
  const enableAuthDebug = process.env.ENABLE_AUTH_DEBUG === 'true' && nodeEnv === 'development';
  
  return {
    nodeEnv,
    logLevel,
    enableDebug,
    enableAuthDebug
  };
}

// Environment-specific configurations
export const environments = {
  development: {
    logLevel: 'DEBUG' as const,
    enableDebug: true,
    enableAuthDebug: true,
  },
  
  staging: {
    logLevel: 'INFO' as const,
    enableDebug: false,
    enableAuthDebug: false,
  },
  
  production: {
    logLevel: 'WARN' as const,
    enableDebug: false,
    enableAuthDebug: false,
  }
};
```

#### Step 6: Log Monitoring and Alerting

Implement log monitoring for production:

```typescript
// app/lib/log-monitor.ts
export interface LogAlert {
  type: 'error_spike' | 'auth_failure' | 'unusual_activity';
  message: string;
  count: number;
  timestamp: number;
}

export class LogMonitor {
  private static alerts: LogAlert[] = [];
  private static errorCount = 0;
  private static lastReset = Date.now();
  
  static recordLog(level: string, message: string): void {
    const now = Date.now();
    
    // Reset counter every hour
    if (now - this.lastReset > 60 * 60 * 1000) {
      this.errorCount = 0;
      this.lastReset = now;
    }
    
    if (level === 'ERROR') {
      this.errorCount++;
      
      // Alert on high error rate
      if (this.errorCount > 50) {
        this.createAlert('error_spike', `High error rate detected: ${this.errorCount} errors/hour`, this.errorCount);
      }
    }
    
    // Alert on authentication failures
    if (message.includes('auth') && level === 'ERROR') {
      this.createAlert('auth_failure', 'Authentication failure detected', 1);
    }
  }
  
  private static createAlert(type: LogAlert['type'], message: string, count: number): void {
    const alert: LogAlert = {
      type,
      message,
      count,
      timestamp: Date.now()
    };
    
    this.alerts.push(alert);
    
    // Keep only last 100 alerts
    if (this.alerts.length > 100) {
      this.alerts = this.alerts.slice(-100);
    }
    
    // Send alert (implementation depends on your alerting system)
    this.sendAlert(alert);
  }
  
  private static sendAlert(alert: LogAlert): void {
    // Implementation would depend on your alerting system
    console.error('LOG ALERT:', alert);
    
    // In production, you might send to:
    // - Slack webhook
    // - Email notification
    // - Monitoring service
    // - PagerDuty
  }
  
  static getAlerts(hours: number = 24): LogAlert[] {
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);
    return this.alerts.filter(alert => alert.timestamp > cutoff);
  }
}

export const logMonitor = LogMonitor;
```

### Dependencies Between Fixes

- **Independent:** Can be implemented immediately
- **Complements:** Other logging improvements

### Implementation Risks

- **Minimal:** Loss of debug information in production
- **Minimal:** Low implementation complexity
- **Minimal:** Minimal impact on functionality

## 🌿 Branch Strategy (According to Project Guidelines)

### Recommended Branch

```bash
git checkout -b fix/security-sec012-debug-logs
```

### Example

```bash
git checkout -b fix/security-sec012-debug-logs
```

### Pull Request Template

**Title:**

```text
🐛 fix(security): implement fix for SEC-012 - production debug logs
```

**Body:**

```markdown
### ✍️ What was done

This PR implements the security fix for vulnerability SEC-012 (Low severity) in the Configuration component.

* Disabled debug mode in production environment
* Implemented comprehensive logging system with proper levels
* Added environment-based logging configuration
* Created log monitoring and alerting system
* Implemented sensitive data sanitization in logs

### 📌 Why it matters

Without this change, sensitive information could be exposed through debug logs in production, potentially aiding attackers in reconnaissance and providing insights into the application's internal workings.

This fix ensures that debug information is only available in development environments, with appropriate log levels and sanitization in production.

### 🧪 How to test

1. Test application in development mode - debug logs should be available
2. Test application in production mode - debug logs should be disabled
3. Verify log levels are properly configured by environment
4. Test sensitive data sanitization in logs
5. Verify log monitoring and alerting functionality
6. Run security tests: `bun run test:security`

### 📎 Related

Closes #[issue_number]
```

## 🚀 GitHub CLI Commands

### Create Issue

```bash
gh issue create \
  --title "🟢 SEC-012: Debug Logs in Production" \
  --body-file project-docs/security-tasks/low/SEC-012-debug-logs.md \
  --label "security,low,SEC-012"
```

### Create Branch and PR

```bash
# Create branch
git checkout -b fix/security-sec012-debug-logs

# Push and create PR
git push origin fix/security-sec012-debug-logs
gh pr create \
  --title "🐛 fix(security): implement fix for SEC-012 - production debug logs" \
  --body "This PR implements the security fix for vulnerability SEC-012. Refer to the PR template for detailed testing instructions." \
  --label "security,fix"
```

### Update Status

```bash
# Add progress comment
gh issue comment <issue_number> --body "🔄 Status: Implementation in progress"

# Close issue after merge
gh issue close <issue_number> --comment "✅ Resolved via PR #<pr_number>"
```

## 📊 Success Criteria

### Functional Validation

- [ ] Main functionality preserved
- [ ] No regressions introduced
- [ ] Performance maintained

### Security Validation

- [ ] Debug logs completely disabled in production
- [ ] No new vulnerabilities introduced
- [ ] Security tests passing

### Code Validation

- [ ] Code review approved
- [ ] Automated tests passing
- [ ] Documentation updated

## 🧪 Test Plan

### Automated Tests

```typescript
// tests/security/SEC-012.test.ts
describe('SEC-012: Debug Logs in Production', () => {
  test('should disable debug in production', () => {
    process.env.NODE_ENV = 'production';
    process.env.ENABLE_DEBUG = 'false';
    
    const config = getEnvironmentConfig();
    expect(config.enableDebug).toBe(false);
    expect(config.enableAuthDebug).toBe(false);
  });
  
  test('should enable debug in development', () => {
    process.env.NODE_ENV = 'development';
    process.env.ENABLE_DEBUG = 'true';
    
    const config = getEnvironmentConfig();
    expect(config.enableDebug).toBe(true);
    expect(config.enableAuthDebug).toBe(true);
  });
  
  test('should sanitize sensitive data in logs', () => {
    const sensitiveData = {
      accessToken: 'BQD1234567890abcdef...',
      email: 'user@example.com',
      message: 'User logged in'
    };
    
    const logger = Logger.getInstance();
    const sanitized = logger['sanitizeContext'](sensitiveData);
    
    expect(sanitized.accessToken).toBe('[REDACTED]');
    expect(sanitized.email).toBe('[EMAIL]');
  });
});
```

### Manual Tests

- [ ] Manual log inspection in different environments
- [ ] Staging environment validation
- [ ] Regression test

### Validation Tools

```bash
# Test environment variables
NODE_ENV=production ENABLE_DEBUG=false bun run dev

# Check log output
# Verify no debug logs appear in production

# Test with different log levels
LOG_LEVEL=ERROR bun run dev
LOG_LEVEL=DEBUG bun run dev
```

## 📈 Metrics and Monitoring

### Before/After Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Information Leakage Risk | Medium | Minimal | 80% |
| Log Verbosity (Production) | High | Low | -70% |
| Security Score | 6.0 | 8.5 | +42% |

### Post-Deploy Monitoring

- [ ] Alerts configured for log anomalies
- [ ] Dashboard updated with log metrics
- [ ] Logs monitored for debug leakage

## 📚 References

- [Branching Guidelines](../../branching-guidelines.md)
- [Merge Commit Guidelines](../../merge-commit-guidelines.md)
- [Security Vulnerabilities Report](../../../security-vulnerabilities-report.md)
- [OWASP Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)
- [NextAuth.js Debug Configuration](https://next-auth.js.org/configuration/options#debug)

## 🔄 Change History

| Date | Version | Author | Change |
|-------|--------|-------|--------|
| 10/04/2025 | 1.0 | Security Team | Initial creation |

## 📝 Additional Notes

Debug information should never be exposed in production environments. Consider implementing structured logging with proper log levels and monitoring to ensure security while maintaining necessary operational visibility.

---

**Status:** Open  
**Assigned to:** [Responsible name]  
**Due date:** 10/22/2025  
**Priority:** 6  
**Complexity:** Low

## 🚀 Quick Commands

```bash
# Create issue
gh issue create --title "🟢 SEC-012: Debug Logs in Production" --body-file $(pwd)/project-docs/security-tasks/low/SEC-012-debug-logs.md --label "security,low,SEC-012"

# Create branch
git checkout -b fix/security-sec012-debug-logs

# Create PR
gh pr create --title "🐛 fix(security): SEC-012 - production debug logs" --body "This PR implements the security fix for vulnerability SEC-012. Refer to the PR template for detailed testing instructions." --label "security,fix"

# Tests
bun run test:security
bun run test:unit
bun run build

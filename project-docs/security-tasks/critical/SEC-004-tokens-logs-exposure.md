# 🔴 SEC-004: OAuth Tokens Exposed in Logs

## 📋 Basic Information

| Field | Value |
|-------|-------|
| **Vulnerability ID** | SEC-004 |
| **Severity** | Critical |
| **CVSS Score** | 8.7 |
| **Component** | Logging |
| **Location** | `app/lib/security-logger.ts:122-127` |
| **Discovery Date** | 10/04/2025 |
| **Status** | Open |

## 🎯 Description

Despite the sanitization mechanism, security logs can still contain unmasked OAuth tokens, especially in error cases or debug scenarios.

### Potential Impact

- Token leakage through server logs
- Account compromise via log analysis
- Compliance violations (LGPD, GDPR)
- Long-term credential exposure

### Exploitation Examples

```javascript
// Logs might contain unmasked tokens in error scenarios
console.log(`[SECURITY] ${eventType}`, {
  ...entry,
  timestamp: new Date(entry.timestamp).toISOString(),
  // accessToken might be exposed here
});
```

### Evidence Found

```typescript
console.log(`[SECURITY] ${eventType}`, {
  ...entry,
  timestamp: new Date(entry.timestamp).toISOString(),
});
```

## 🔧 Remediation Plan

### Specific Actions Required

1. Improve token sanitization in logs
2. Implement complete OAuth token masking
3. Add sensitive data validation before logging
4. Implement appropriate log levels

### Detailed Remediation Steps

#### Step 1: Enhance Sanitization Function

Improve the sanitization function to detect and mask all token patterns.

```typescript
// app/lib/security-logger.ts
function sanitizeLogData(data: unknown): unknown {
  if (typeof data !== 'object' || data === null) {
    return data;
  }
  
  const sanitized = Array.isArray(data) ? [...data] : { ...data };
  
  // Token patterns to detect and mask
  const tokenPatterns = [
    /BQ[\w-]{100,}/g, // Spotify access token pattern
    /[\w-]{100,}/g,   // Generic long tokens
    /[A-Za-z0-9]{22}/g, // Spotify ID pattern
    /sk_[\w-]{24,}/g,  // Stripe keys pattern
    /ghs_[\w-]{36}/g,  // GitHub token pattern
  ];
  
  // Recursive sanitization function
  function sanitizeRecursive(obj: any): any {
    if (typeof obj !== 'object' || obj === null) {
      if (typeof obj === 'string') {
        let sanitized = obj;
        tokenPatterns.forEach(pattern => {
          sanitized = sanitized.replace(pattern, (match) => {
            return match.length > 10 
              ? `${match.substring(0, 4)}...${match.substring(match.length - 4)}`
              : '***';
          });
        });
        return sanitized;
      }
      return obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(sanitizeRecursive);
    }
    
    const result: any = {};
    for (const [key, value] of Object.entries(obj)) {
      // Skip sensitive keys entirely
      if (isSensitiveKey(key)) {
        result[key] = '[REDACTED]';
      } else {
        result[key] = sanitizeRecursive(value);
      }
    }
    return result;
  }
  
  return sanitizeRecursive(sanitized);
}

function isSensitiveKey(key: string): boolean {
  const sensitiveKeys = [
    'token', 'accesstoken', 'refreshtoken', 'clientsecret',
    'password', 'secret', 'key', 'authorization', 'bearer',
    'credentials', 'auth', 'session', 'cookie'
  ];
  
  return sensitiveKeys.some(sensitive => 
    key.toLowerCase().includes(sensitive.toLowerCase())
  );
}
```

#### Step 2: Implement Advanced Masking

Add sophisticated token detection and masking with hashing for tracking.

```typescript
// app/lib/token-masking.ts
export class TokenMasker {
  private static tokenHashes = new Map<string, string>();
  
  static maskToken(token: string): string {
    if (!token || typeof token !== 'string') {
      return token;
    }
    
    // Check if we've seen this token before
    const existingHash = this.tokenHashes.get(token);
    if (existingHash) {
      return existingHash;
    }
    
    // Create masked version
    const masked = this.createMaskedToken(token);
    const hash = this.createTokenHash(token);
    
    // Store for consistency
    this.tokenHashes.set(token, masked);
    
    return masked;
  }
  
  private static createMaskedToken(token: string): string {
    if (token.length <= 8) {
      return '***';
    }
    
    const prefix = token.substring(0, 4);
    const suffix = token.substring(token.length - 4);
    const maskLength = Math.max(3, token.length - 8);
    const mask = '*'.repeat(maskLength);
    
    return `${prefix}${mask}${suffix}`;
  }
  
  private static createTokenHash(token: string): string {
    // Create a hash for tracking without exposing the token
    return crypto.createHash('sha256')
      .update(token + 'salt')
      .digest('hex')
      .substring(0, 8);
  }
  
  static clearCache(): void {
    this.tokenHashes.clear();
  }
}
```

#### Step 3: Configure Log Levels

Implement proper log level configuration based on environment.

```typescript
// app/lib/logger-config.ts
enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

class Logger {
  private static instance: Logger;
  private logLevel: LogLevel;
  
  private constructor() {
    this.logLevel = this.getLogLevelFromEnv();
  }
  
  private getLogLevelFromEnv(): LogLevel {
    const envLevel = process.env.LOG_LEVEL?.toUpperCase();
    switch (envLevel) {
      case 'ERROR': return LogLevel.ERROR;
      case 'WARN': return LogLevel.WARN;
      case 'INFO': return LogLevel.INFO;
      case 'DEBUG': return LogLevel.DEBUG;
      default: 
        return process.env.NODE_ENV === 'production' ? LogLevel.WARN : LogLevel.DEBUG;
    }
  }
  
  security(level: 'error' | 'warn' | 'info', event: string, data?: unknown): void {
    if (process.env.NODE_ENV === 'production' && level === 'info') return;
    
    const logLevel = this.getLogLevelFromString(level);
    if (this.logLevel < logLevel) return;
    
    const sanitizedData = sanitizeLogData(data);
    console.log(`[SECURITY-${level.toUpperCase()}] ${event}`, sanitizedData);
  }
  
  private getLogLevelFromString(level: string): LogLevel {
    switch (level) {
      case 'error': return LogLevel.ERROR;
      case 'warn': return LogLevel.WARN;
      case 'info': return LogLevel.INFO;
      case 'debug': return LogLevel.DEBUG;
      default: return LogLevel.INFO;
    }
  }
  
  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }
}

export const logger = Logger.getInstance();
```

#### Step 4: Add Pre-Log Validation

Implement validation to prevent sensitive data from being logged.

```typescript
// app/lib/log-validator.ts
export class LogValidator {
  static validateBeforeLog(data: unknown): { isValid: boolean; sanitized: unknown; warnings: string[] } {
    const warnings: string[] = [];
    let sanitized = data;
    
    // Check for potential sensitive data
    const sensitivePatterns = [
      { pattern: /BQ[\w-]{100,}/g, name: 'Spotify access token' },
      { pattern: /sk_[\w-]{24,}/g, name: 'Stripe API key' },
      { pattern: /ghs_[\w-]{36}/g, name: 'GitHub token' },
      { pattern: /[\w-]{100,}/g, name: 'Long token-like string' },
    ];
    
    const dataStr = JSON.stringify(data);
    let hasSensitiveData = false;
    
    sensitivePatterns.forEach(({ pattern, name }) => {
      if (pattern.test(dataStr)) {
        hasSensitiveData = true;
        warnings.push(`Potential ${name} detected in log data`);
      }
    });
    
    if (hasSensitiveData) {
      sanitized = sanitizeLogData(data);
      warnings.push('Data has been sanitized for security');
    }
    
    return {
      isValid: true,
      sanitized,
      warnings
    };
  }
}
```

### Dependencies Between Fixes

- **Independent:** Can be implemented immediately
- **Complements:** Other security fixes

### Implementation Risks

- **Low:** Possible loss of debugging information
- **Low:** Additional complexity in sanitization
- **Minimal:** Minimal impact on functionality

## 🌿 Branch Strategy (According to Project Guidelines)

### Recommended Branch

```bash
git checkout -b fix/security-sec004-tokens-logs-exposure
```

### Example

```bash
git checkout -b fix/security-sec004-tokens-logs-exposure
```

### Pull Request Template

**Title:**

```text
🐛 fix(security): implement fix for SEC-004 - tokens logs exposure
```

**Body:**

```markdown
### ✍️ What was done

This PR implements the security fix for vulnerability SEC-004 (critical severity) in the Logging component.

* Enhanced token sanitization to detect and mask all OAuth token patterns
* Added proper input validation before logging sensitive data
* Implemented secure logging practices with environment-based log levels
* Added advanced token masking with consistent hashing for tracking
* Updated logging system to prevent sensitive data exposure

### 📌 Why it matters

Without this change, the application is vulnerable to token leakage through server logs, which could lead to account compromise and compliance violations. Attackers with access to logs could extract OAuth tokens and gain unauthorized access to user accounts.

This fix ensures that sensitive tokens are properly masked in logs and helps prevent token leakage by implementing comprehensive sanitization and validation mechanisms before any data is logged.

### 🧪 How to test

1. Start the application and trigger various authentication flows
2. Check that logs no longer contain unmasked tokens
3. Verify that token patterns are consistently masked
4. Test that error scenarios don't expose sensitive data
5. Validate that different log levels work correctly
6. Run security tests: `bun run test:security`

### 📎 Related

Closes #[issue_number]
Depends on #[dependency_issue_number]
```

## 🚀 GitHub CLI Commands

### Create Issue

```bash
gh issue create \
  --title "🔴 SEC-004: OAuth Tokens Exposed in Logs" \
  --body-file project-docs/security-tasks/critical/SEC-004-tokens-logs-exposure.md \
  --label "security,critical,SEC-004"
```

### Create Branch and PR

```bash
# Create branch
git checkout -b fix/security-sec004-tokens-logs-exposure

# Push and create PR
git push origin fix/security-sec004-tokens-logs-exposure
gh pr create \
  --title "🐛 fix(security): implement fix for SEC-004 - tokens logs exposure" \
  --body "This PR implements the security fix for vulnerability SEC-004. Refer to the PR template for detailed testing instructions." \
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

- [ ] Vulnerability completely mitigated
- [ ] No new vulnerabilities introduced
- [ ] Security tests passing

### Code Validation

- [ ] Code review approved
- [ ] Automated tests passing
- [ ] Documentation updated

## 🧪 Test Plan

### Automated Tests

```typescript
// tests/security/SEC-004.test.ts
describe('SEC-004: Token Log Exposure', () => {
  test('should mask Spotify access tokens in logs', () => {
    const token = 'BQ1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const masked = TokenMasker.maskToken(token);
    
    expect(masked).toBe('BQ12...def0');
    expect(masked).not.toBe(token);
  });
  
  test('should sanitize log data properly', () => {
    const data = {
      accessToken: 'BQ1234567890abcdef',
      user: 'testuser',
      clientId: 'testclient'
    };
    
    const sanitized = sanitizeLogData(data);
    expect(sanitized.accessToken).not.toBe(data.accessToken);
    expect(sanitized.user).toBe(data.user);
  });
});
```

### Manual Tests

- [ ] Log inspection during authentication
- [ ] Staging environment validation
- [ ] Regression test

### Validation Tools

```bash
# Test log sanitization
bun run test:security

# Monitor logs for token exposure
tail -f logs/application.log | grep -i "token" || echo "✅ No tokens found in logs"

# Test different log levels
LOG_LEVEL=ERROR bun run dev
LOG_LEVEL=DEBUG bun run dev
```

## 📈 Metrics and Monitoring

### Before/After Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Token Exposure Risk | High | None | 100% |
| Log Security | Low | High | 400% |
| Compliance Risk | High | Low | 80% |

### Post-Deploy Monitoring

- [ ] Alerts configured for token detection attempts
- [ ] Dashboard updated with log security metrics
- [ ] Logs monitored for sanitization effectiveness

## 📚 References

- [Branching Guidelines](../../branching-guidelines.md)
- [Merge Commit Guidelines](../../merge-commit-guidelines.md)
- [Security Vulnerabilities Report](../../../security-vulnerabilities-report.md)
- [OWASP Top 10 - A09:2021 Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [NIST Guidelines for Secure Logging](https://csrc.nist.gov/publications/detail/sp/800-92/final)

## 🔄 Change History

| Date | Version | Author | Change |
|-------|--------|-------|--------|
| 10/04/2025 | 1.0 | Security Team | Initial creation |

## 📝 Additional Notes

This vulnerability is critical as it affects the long-term security of the application through log retention. The fix must ensure comprehensive coverage of all token patterns while maintaining useful logging capabilities.

---

**Status:** Open  
**Assigned to:** [Responsible name]  
**Due date:** 10/05/2025  
**Priority:** 4  
**Complexity:** Low

## 🚀 Quick Commands

```bash
# Create issue
gh issue create --title "🔴 SEC-004: Tokens Logs Exposure" --body-file $(pwd)/project-docs/security-tasks/critical/SEC-004-tokens-logs-exposure.md --label "security,critical,SEC-004"

# Create branch
git checkout -b fix/security-sec004-tokens-logs-exposure

# Create PR
gh pr create --title "🐛 fix(security): SEC-004 - tokens logs exposure" --body "This PR implements the security fix for vulnerability SEC-004. Refer to the PR template for detailed testing instructions." --label "security,fix"

# Tests
bun run test:security
bun run test:unit
bun run build

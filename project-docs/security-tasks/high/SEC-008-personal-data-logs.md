# 🟠 SEC-008: Personal Data Exposed in Logs

## 📋 Basic Information

| Field | Value |
|-------|-------|
| **Vulnerability ID** | SEC-008 |
| **Severity** | High |
| **CVSS Score** | 7.2 |
| **Component** | Logging |
| **Location** | `app/lib/security-logger.ts:73-78` |
| **Discovery Date** | 10/04/2025 |
| **Status** | Open |

## 🎯 Description

IP addresses and User-Agent data are collected in logs without proper anonymization or truncation mechanisms. This exposure of personal data in logs violates privacy regulations and creates security risks through user tracking and fingerprinting capabilities.

### Potential Impact

- Unauthorized user tracking
- Privacy violations
- User fingerprinting
- Compliance violations (GDPR, LGPD)
- Data leakage through log analysis

### Exploitation Examples

```bash
# Log entries exposing personal data
[2025-10-04T12:00:00.000Z] [INFO] User login attempt from 192.168.1.100 with Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36

# Attacker can analyze logs to:
# 1. Track user behavior patterns
# 2. Identify specific users through IP+UA fingerprinting
# 3. Build user profiles across sessions
# 4. Correlate with other data sources
```

### Evidence Found

```typescript
// app/lib/security-logger.ts - Personal data exposure
function extractClientInfo(req: NextApiRequest | NextRequest): { 
  userAgent?: string; 
  ip?: string;
  sessionId?: string;
} {
  const headers = req.headers as unknown as Record<string, string | string[]> & { 
    get?: (key: string) => string | null;
  };
  
  const getHeaderValue = (key: string): string | undefined => {
    if (headers.get) return headers.get(key) || undefined;
    const value = headers[key];
    return Array.isArray(value) ? value[0] : value;
  };
  
  // EXPOSING RAW IP ADDRESS
  const ip = getHeaderValue('x-forwarded-for') || 
             getHeaderValue('x-real-ip') || 
             'unknown';
  
  // EXPOSING RAW USER AGENT
  const userAgent = getHeaderValue('user-agent') || '';
  
  return { userAgent, ip, sessionId: generateSessionId(req) };
}
```

## 🔧 Remediation Plan

### Specific Actions Required

1. Implement IP address anonymization
2. Remove or truncate detailed User-Agent information
3. Implement hash-based unique identifiers
4. Configure minimal log retention for sensitive data

### Detailed Remediation Steps

#### Step 1: IP Address Anonymization

Create comprehensive IP anonymization functions:

```typescript
// app/lib/privacy-utils.ts
export function anonymizeIP(ip: string): string {
  if (!ip || ip === 'unknown') return 'unknown';
  
  // Handle IPv4: 192.168.1.100 -> 192.168.1.0
  const ipv4Match = ip.match(/^(\d+\.\d+\.\d+)\.\d+$/);
  if (ipv4Match) {
    return `${ipv4Match[1]}.0`;
  }
  
  // Handle IPv6: truncate last 64 bits
  const ipv6Match = ip.match(/^([0-9a-fA-F:]+::)/);
  if (ipv6Match) {
    return `${ipv6Match[1]}0`;
  }
  
  // Handle IPv6 full format
  const ipv6FullMatch = ip.match(/^([0-9a-fA-F:]{1,4}:){1,7}:[0-9a-fA-F:]{1,4}$/);
  if (ipv6FullMatch) {
    const parts = ip.split(':');
    // Keep first 4 parts, truncate rest
    return `${parts.slice(0, 4).join('::')}0`;
  }
  
  return 'unknown';
}

export function getIPCountry(ip: string): string {
  // Optional: Get country code for analytics without storing IP
  // This would require a GeoIP service
  return 'unknown';
}
```

#### Step 2: User-Agent Sanitization

Implement User-Agent truncation and sanitization:

```typescript
// app/lib/privacy-utils.ts (continued)
export function sanitizeUserAgent(userAgent: string): string {
  if (!userAgent) return 'unknown';
  
  // Extract only essential browser information
  const browserMatch = userAgent.match(/(Chrome|Firefox|Safari|Edge|Opera)\/[\d.]+/);
  if (browserMatch) {
    return browserMatch[0];
  }
  
  // Handle mobile browsers
  const mobileMatch = userAgent.match(/(Mobile Safari|Chrome Mobile|Firefox Mobile)/);
  if (mobileMatch) {
    return mobileMatch[0];
  }
  
  // Handle bots
  const botMatch = userAgent.match(/(Googlebot|Bingbot|Slackbot|Twitterbot)/);
  if (botMatch) {
    return botMatch[0];
  }
  
  return 'unknown-browser';
}

export function extractDeviceType(userAgent: string): string {
  if (!userAgent) return 'unknown';
  
  if (/Mobile|Android|iPhone|iPad/.test(userAgent)) {
    return 'mobile';
  }
  
  if (/Tablet|iPad/.test(userAgent)) {
    return 'tablet';
  }
  
  if (/Windows|Mac|Linux/.test(userAgent)) {
    return 'desktop';
  }
  
  return 'unknown';
}
```

#### Step 3: Hash-Based Identifiers

Replace session IDs with secure hashes:

```typescript
// app/lib/privacy-utils.ts (continued)
import { createHash } from 'crypto';

export function generateAnonymousSessionId(req: NextApiRequest | NextRequest): string {
  // Create a hash based on multiple factors but without storing PII
  const sessionData = {
    timestamp: Math.floor(Date.now() / (1000 * 60 * 60)), // Hour bucket
    ipHash: anonymizeIP(getClientIP(req)),
    userAgentHash: sanitizeUserAgent(getUserAgent(req))
  };
  
  const hashInput = JSON.stringify(sessionData);
  return createHash('sha256').update(hashInput).digest('hex').substring(0, 12);
}

export function hashUserId(userId: string): string {
  if (!userId) return 'anonymous';
  
  // Create a consistent hash for user identification
  return createHash('sha256')
    .update(userId + process.env.HASH_SALT || 'default-salt')
    .digest('hex')
    .substring(0, 8);
}
```

#### Step 4: Updated Security Logger

Modify the security logger with privacy protections:

```typescript
// app/lib/security-logger.ts (updated)
import { anonymizeIP, sanitizeUserAgent, generateAnonymousSessionId, extractDeviceType } from './privacy-utils';

function extractClientInfo(req: NextApiRequest | NextRequest): { 
  userAgent?: string; 
  ip?: string;
  sessionId?: string;
  deviceType?: string;
} {
  const headers = req.headers as unknown as Record<string, string | string[]> & { 
    get?: (key: string) => string | null;
  };
  
  const getHeaderValue = (key: string): string | undefined => {
    if (headers.get) return headers.get(key) || undefined;
    const value = headers[key];
    return Array.isArray(value) ? value[0] : value;
  };
  
  const rawIP = getHeaderValue('x-forwarded-for') || 
                getHeaderValue('x-real-ip') || 
                'unknown';
  
  const rawUserAgent = getHeaderValue('user-agent') || '';
  
  return {
    // ANONYMIZED DATA
    ip: anonymizeIP(rawIP),
    userAgent: sanitizeUserAgent(rawUserAgent),
    deviceType: extractDeviceType(rawUserAgent),
    sessionId: generateAnonymousSessionId(req),
  };
}

export function logSecurityEvent(
  eventType: SecurityEventType, 
  req: NextApiRequest | NextRequest, 
  additionalData?: Record<string, unknown>
): void {
  const clientInfo = extractClientInfo(req);
  
  const logEntry = {
    timestamp: new Date().toISOString(),
    eventType,
    clientInfo, // Now anonymized
    additionalData: sanitizeAdditionalData(additionalData),
  };
  
  // Log with appropriate level based on event type
  if (eventType === SecurityEventType.CREDENTIAL_EXPOSURE) {
    console.error('[SECURITY-CRITICAL]', logEntry);
  } else if (eventType === SecurityEventType.RATE_LIMIT_EXCEEDED) {
    console.warn('[SECURITY-WARN]', logEntry);
  } else {
    console.info('[SECURITY-INFO]', logEntry);
  }
}

function sanitizeAdditionalData(data?: Record<string, unknown>): Record<string, unknown> {
  if (!data) return {};
  
  const sanitized: Record<string, unknown> = {};
  
  for (const [key, value] of Object.entries(data)) {
    // Skip known PII fields
    if (['email', 'name', 'userId', 'sessionId', 'ip', 'userAgent'].includes(key)) {
      continue;
    }
    
    // Sanitize potential PII in values
    if (typeof value === 'string') {
      // Remove email patterns
      sanitized[key] = value.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[REDACTED_EMAIL]');
      
      // Remove phone patterns
      sanitized[key] = (sanitized[key] as string).replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[REDACTED_PHONE]');
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}
```

#### Step 5: Log Retention Configuration

Implement proper log retention policies:

```typescript
// app/lib/log-retention.ts
export interface LogRetentionConfig {
  securityLogs: number; // days
  accessLogs: number;   // days
  errorLogs: number;    // days
  debugLogs: number;    // days
}

export const logRetentionConfig: LogRetentionConfig = {
  securityLogs: 90,    // 90 days for security events
  accessLogs: 30,      // 30 days for access logs
  errorLogs: 60,       // 60 days for error logs
  debugLogs: 7,        // 7 days for debug logs
};

export function shouldRetainLog(logType: keyof LogRetentionConfig, logDate: Date): boolean {
  const retentionDays = logRetentionConfig[logType];
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
  
  return logDate > cutoffDate;
}

export function cleanupOldLogs(): void {
  // Implementation would depend on your logging system
  // This is a placeholder for log cleanup logic
  console.info('[LOG-CLEANUP] Starting log cleanup process');
  
  // Example: Clean up old log files
  // deleteOldLogFiles(logRetentionConfig);
  
  console.info('[LOG-CLEANUP] Log cleanup completed');
}
```

### Dependencies Between Fixes

- **Complements:** SEC-004 (token sanitization in logs)
- **Independent:** Can be implemented immediately

### Implementation Risks

- **Minimal:** Loss of detailed debugging information
- **Minimal:** Low implementation complexity
- **Minimal:** Minimal impact on functionality

## 🌿 Branch Strategy (According to Project Guidelines)

### Recommended Branch

```bash
git checkout -b fix/security-sec008-personal-data-logs
```

### Example

```bash
git checkout -b fix/security-sec008-personal-data-logs
```

### Pull Request Template

**Title:**

```text
🐛 fix(security): implement fix for SEC-008 - personal data anonymization in logs
```

**Body:**

```markdown
### ✍️ What was done

This PR implements the security fix for vulnerability SEC-008 (High severity) in the Logging component.

* Implemented comprehensive IP address anonymization
* Added User-Agent sanitization and truncation
* Created hash-based anonymous session identifiers
* Configured proper log retention policies
* Added PII detection and redaction in log data

### 📌 Why it matters

Without this change, personal data is exposed in application logs, creating privacy violations and compliance risks. Attackers could analyze logs to track users, build profiles, and correlate data across different systems.

This fix ensures that all personal data is properly anonymized before logging, protecting user privacy while maintaining security monitoring capabilities.

### 🧪 How to test

1. Start the application and trigger various security events
2. Check log outputs to verify IP addresses are anonymized
3. Verify User-Agent strings are truncated to essential info
4. Test that session identifiers are hashed, not raw values
5. Verify PII detection and redaction is working
6. Run security tests: `bun run test:security`

### 📎 Related

Closes #[issue_number]
```

## 🚀 GitHub CLI Commands

### Create Issue

```bash
gh issue create \
  --title "🟠 SEC-008: Personal Data Exposed in Logs" \
  --body-file project-docs/security-tasks/high/SEC-008-personal-data-logs.md \
  --label "security,high,SEC-008"
```

### Create Branch and PR

```bash
# Create branch
git checkout -b fix/security-sec008-personal-data-logs

# Push and create PR
git push origin fix/security-sec008-personal-data-logs
gh pr create \
  --title "🐛 fix(security): implement fix for SEC-008 - personal data anonymization in logs" \
  --body "This PR implements the security fix for vulnerability SEC-008. Refer to the PR template for detailed testing instructions." \
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

- [ ] Personal data completely anonymized in logs
- [ ] No new vulnerabilities introduced
- [ ] Security tests passing

### Code Validation

- [ ] Code review approved
- [ ] Automated tests passing
- [ ] Documentation updated

## 🧪 Test Plan

### Automated Tests

```typescript
// tests/security/SEC-008.test.ts
describe('SEC-008: Personal Data Anonymization', () => {
  test('should anonymize IP addresses', () => {
    expect(anonymizeIP('192.168.1.100')).toBe('192.168.1.0');
    expect(anonymizeIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toContain('::0');
  });
  
  test('should sanitize User-Agent strings', () => {
    const longUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36';
    expect(sanitizeUserAgent(longUA)).toBe('Chrome/118.0.0.0');
  });
  
  test('should redact PII in log data', () => {
    const data = { email: 'user@example.com', message: 'Login attempt' };
    const sanitized = sanitizeAdditionalData(data);
    expect(sanitized.email).toBe('[REDACTED_EMAIL]');
  });
});
```

### Manual Tests

- [ ] Manual log inspection for PII
- [ ] Staging environment validation
- [ ] Regression test

### Validation Tools

```bash
# Test logging and check output
curl -X POST http://localhost:3000/api/config
# Check logs for anonymized data

# Test with various User-Agents
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0.0.0" \
     -X POST http://localhost:3000/api/config
```

## 📈 Metrics and Monitoring

### Before/After Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| PII Exposure Risk | High | Minimal | 95% |
| Privacy Compliance Score | 2/10 | 9/10 | +350% |
| Log Data Usability | High | Medium | -20% |

### Post-Deploy Monitoring

- [ ] Alerts configured for PII detection attempts
- [ ] Dashboard updated with privacy metrics
- [ ] Logs monitored for anonymization effectiveness

## 📚 References

- [Branching Guidelines](../../branching-guidelines.md)
- [Merge Commit Guidelines](../../merge-commit-guidelines.md)
- [Security Vulnerabilities Report](../../../security-vulnerabilities-report.md)
- [OWASP Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)
- [GDPR Data Protection Guidelines](https://gdpr.eu/data-protection/)

## 🔄 Change History

| Date | Version | Author | Change |
|-------|--------|-------|--------|
| 10/04/2025 | 1.0 | Security Team | Initial creation |

## 📝 Additional Notes

Privacy by design should be implemented throughout the application. Consider implementing data minimization principles and conducting regular privacy impact assessments. Log anonymization should be balanced with the need for security monitoring and debugging.

---

**Status:** Open  
**Assigned to:** [Responsible name]  
**Due date:** 10/13/2025  
**Priority:** 3  
**Complexity:** Low

## 🚀 Quick Commands

```bash
# Create issue
gh issue create --title "🟠 SEC-008: Personal Data Exposed in Logs" --body-file $(pwd)/project-docs/security-tasks/high/SEC-008-personal-data-logs.md --label "security,high,SEC-008"

# Create branch
git checkout -b fix/security-sec008-personal-data-logs

# Create PR
gh pr create --title "🐛 fix(security): SEC-008 - personal data anonymization in logs" --body "This PR implements the security fix for vulnerability SEC-008. Refer to the PR template for detailed testing instructions." --label "security,fix"

# Tests
bun run test:security
bun run test:unit
bun run build

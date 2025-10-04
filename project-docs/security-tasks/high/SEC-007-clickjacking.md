# 🟠 SEC-007: ClickJacking Vulnerability

## 📋 Basic Information

| Field | Value |
|-------|-------|
| **Vulnerability ID** | SEC-007 |
| **Severity** | High |
| **CVSS Score** | 6.5 |
| **Component** | Frontend |
| **Location** | `app/layout.tsx` (partially mitigated) |
| **Discovery Date** | 10/04/2025 |
| **Status** | Open |

## 🎯 Description

Although the `X-Frame-Options: DENY` header is configured, other ClickJacking protections such as `Content-Security-Policy: frame-ancestors` are not implemented. This partial protection leaves the application vulnerable to sophisticated ClickJacking attacks that could bypass existing defenses.

### Potential Impact

- ClickJacking attacks through invisible frames
- Phishing through hidden frames
- User click theft and unauthorized actions
- UI redress attacks
- Credential theft through deceptive interfaces

### Exploitation Examples

```html
<!-- ClickJacking attack with transparent overlay -->
<!DOCTYPE html>
<html>
<head>
  <style>
    .overlay {
      position: absolute;
      top: 0;
      left: 0;
      opacity: 0.0;
      filter: alpha(opacity=0);
      width: 300px;
      height: 200px;
    }
    .decoy {
      position: absolute;
      top: 0;
      left: 0;
      width: 300px;
      height: 200px;
      background: url('fake-button.png');
    }
  </style>
</head>
<body>
  <div class="decoy">Click here to win a prize!</div>
  <iframe class="overlay" src="http://localhost:3000/config"></iframe>
</body>
</html>
```

### Evidence Found

```typescript
// app/layout.tsx - Incomplete ClickJacking protection
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        {/* Only X-Frame-Options is implemented */}
        <meta httpEquiv="X-Frame-Options" content="DENY" />
        {/* Missing CSP frame-ancestors directive */}
        {/* Missing JavaScript frame-busting */}
      </head>
      <body>
        {children}
      </body>
    </html>
  );
}
```

## 🔧 Remediation Plan

### Specific Actions Required

1. Implement complete Content Security Policy
2. Add frame-ancestors directive to CSP
3. Implement frame protection on all pages
4. Add JavaScript anti-ClickJacking as fallback

### Detailed Remediation Steps

#### Step 1: Complete CSP Implementation

Update `app/layout.tsx` with comprehensive CSP:

```typescript
// app/layout.tsx
export default function RootLayout({ children }: { children: React.ReactNode }) {
  const cspContent = `
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'nonce-${generateNonce()}';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self' https://api.spotify.com;
    frame-ancestors 'none';
    frame-src 'none';
    form-action 'self';
    base-uri 'self';
    upgrade-insecure-requests;
  `.replace(/\s+/g, ' ').trim();

  return (
    <html lang="en">
      <head>
        <meta httpEquiv="Content-Security-Policy" content={cspContent} />
        <meta httpEquiv="X-Frame-Options" content="DENY" />
        <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
        <meta httpEquiv="Referrer-Policy" content="strict-origin-when-cross-origin" />
        <script
          dangerouslySetInnerHTML={{
            __html: `
              if (self !== top) {
                // Frame-busting script
                top.location = self.location;
              }
              // Additional protection
              if (window.top !== window.self) {
                window.top.location = window.self.location;
              }
            `
          }}
        />
      </head>
      <body>
        {children}
      </body>
    </html>
  );
}

function generateNonce(): string {
  return crypto.randomBytes(16).toString('base64');
}
```

#### Step 2: Enhanced Security Headers

Create `app/lib/security-headers.ts` for comprehensive header management:

```typescript
import { NextResponse } from 'next/server';

export function addSecurityHeaders(response: NextResponse): NextResponse {
  const securityHeaders = {
    // Frame protection
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': getCSPHeaders(),
    
    // Content type protection
    'X-Content-Type-Options': 'nosniff',
    
    // XSS protection
    'X-XSS-Protection': '1; mode=block',
    
    // HTTPS enforcement
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    
    // Referrer policy
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    
    // Permissions policy
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=()',
    
    // Cross-origin policies
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };

  Object.entries(securityHeaders).forEach(([key, value]) => {
    response.headers.set(key, value);
  });

  return response;
}

function getCSPHeaders(): string {
  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self' https://api.spotify.com",
    "frame-ancestors 'none'",
    "frame-src 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "upgrade-insecure-requests"
  ].join('; ');
}
```

#### Step 3: API Route Protection

Update all API routes with security headers:

```typescript
// app/api/config/route.ts
import { addSecurityHeaders } from '@/app/lib/security-headers';

export async function GET(request: NextRequest) {
  const response = NextResponse.json(config);
  return addSecurityHeaders(response);
}

export async function POST(request: NextRequest) {
  const response = NextResponse.json({ success: true });
  return addSecurityHeaders(response);
}
```

#### Step 4: Client-Side Frame Detection

Create `app/lib/frame-protection.ts` for additional client-side protection:

```typescript
// app/lib/frame-protection.ts
export function initializeFrameProtection(): void {
  // Prevent framing
  if (window.top !== window.self) {
    try {
      window.top.location = window.self.location;
    } catch (e) {
      // If cross-origin, prevent interaction
      document.body.innerHTML = `
        <div style="
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          font-family: Arial, sans-serif;
          background: #f8f9fa;
          color: #dc3545;
          text-align: center;
          padding: 20px;
        ">
          <div>
            <h1>⚠️ Security Warning</h1>
            <p>This application cannot be displayed in a frame for security reasons.</p>
            <p>Please open it directly in your browser.</p>
          </div>
        </div>
      `;
    }
  }

  // Monitor for frame attempts
  let frameCheckInterval = setInterval(() => {
    if (window.top !== window.self) {
      clearInterval(frameCheckInterval);
      window.location.reload();
    }
  }, 1000);

  // Clear interval after 10 seconds
  setTimeout(() => clearInterval(frameCheckInterval), 10000);
}

// CSS-based protection
export const frameProtectionStyles = `
  html, body {
    position: relative;
    z-index: 1;
  }
  
  /* Prevent overlay attacks */
  iframe {
    display: none !important;
  }
  
  /* Prevent ClickJacking with transparent overlays */
  body > * {
    position: relative;
    z-index: 2;
  }
`;
```

#### Step 5: Middleware Implementation

Create middleware for automatic header application:

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { addSecurityHeaders } from './app/lib/security-headers';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  
  // Add security headers to all responses
  return addSecurityHeaders(response);
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
```

### Dependencies Between Fixes

- **Independent:** Can be implemented immediately
- **Complements:** SEC-011 (security headers)

### Implementation Risks

- **Low:** Possible breakage of legitimate iframe usage
- **Minimal:** Minimal implementation complexity
- **Minimal:** Insignificant performance impact

## 🌿 Branch Strategy (According to Project Guidelines)

### Recommended Branch

```bash
git checkout -b fix/security-sec007-ClickJacking
```

### Example

```bash
git checkout -b fix/security-sec007-ClickJacking
```

### Pull Request Template

**Title:**

```text
🐛 fix(security): implement fix for SEC-007 - ClickJacking protection
```

**Body:**

```markdown
### ✍️ What was done

This PR implements the security fix for vulnerability SEC-007 (High severity) in the Frontend component.

* Implemented complete Content Security Policy with frame-ancestors directive
* Added comprehensive security headers to all responses
* Implemented JavaScript frame-busting as fallback protection
* Added client-side frame detection and prevention
* Created middleware for automatic header application

### 📌 Why it matters

Without this change, the application remains vulnerable to sophisticated ClickJacking attacks that could bypass existing X-Frame-Options protection. Attackers could embed the application in invisible frames and trick users into performing unauthorized actions.

This fix ensures comprehensive protection against ClickJacking attacks through multiple layers of defense including CSP headers, JavaScript protection, and continuous frame monitoring.

### 🧪 How to test

1. Start the application and navigate to any page
2. Attempt to embed the application in an iframe - should be blocked
3. Check response headers for CSP and security headers
4. Test frame-busting JavaScript functionality
5. Verify legitimate functionality remains intact
6. Run security tests: `bun run test:security`

### 📎 Related

Closes #[issue_number]
```

## 🚀 GitHub CLI Commands

### Create Issue

```bash
gh issue create \
  --title "🟠 SEC-007: ClickJacking Vulnerability" \
  --body-file project-docs/security-tasks/high/SEC-007-ClickJacking.md \
  --label "security,high,SEC-007"
```

### Create Branch and PR

```bash
# Create branch
git checkout -b fix/security-sec007-ClickJacking

# Push and create PR
git push origin fix/security-sec007-ClickJacking
gh pr create \
  --title "🐛 fix(security): implement fix for SEC-007 - ClickJacking protection" \
  --body "This PR implements the security fix for vulnerability SEC-007. Refer to the PR template for detailed testing instructions." \
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

- [ ] ClickJacking protection completely implemented
- [ ] No new vulnerabilities introduced
- [ ] Security tests passing

### Code Validation

- [ ] Code review approved
- [ ] Automated tests passing
- [ ] Documentation updated

## 🧪 Test Plan

### Automated Tests

```typescript
// tests/security/SEC-007.test.ts
describe('SEC-007: ClickJacking Protection', () => {
  test('should include CSP frame-ancestors header', async () => {
    const response = await GET(new Request('http://localhost:3000/api/config'));
    const cspHeader = response.headers.get('Content-Security-Policy');
    
    expect(cspHeader).toContain("frame-ancestors 'none'");
    expect(cspHeader).toContain("frame-src 'none'");
  });
  
  test('should include X-Frame-Options header', async () => {
    const response = await GET(new Request('http://localhost:3000/api/config'));
    const frameOptions = response.headers.get('X-Frame-Options');
    
    expect(frameOptions).toBe('DENY');
  });
});
```

### Manual Tests

- [ ] Manual iframe embedding test
- [ ] Staging environment validation
- [ ] Regression test

### Validation Tools

```bash
# Check security headers
curl -I http://localhost:3000/api/config

# Test CSP with online tools
# https://csp-evaluator.withgoogle.com/

# Test ClickJacking protection
# Create test HTML with iframe and verify blocking
```

## 📈 Metrics and Monitoring

### Before/After Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| ClickJacking Risk | High | Minimal | 95% |
| Security Headers Score | 3/10 | 9/10 | +200% |
| CSP Coverage | 0% | 100% | +100% |

### Post-Deploy Monitoring

- [ ] Alerts configured for CSP violations
- [ ] Dashboard updated with security metrics
- [ ] Logs monitored for frame attempts

## 📚 References

- [Branching Guidelines](../../branching-guidelines.md)
- [Merge Commit Guidelines](../../merge-commit-guidelines.md)
- [Security Vulnerabilities Report](../../../security-vulnerabilities-report.md)
- [OWASP ClickJacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)

## 🔄 Change History

| Date | Version | Author | Change |
|-------|--------|-------|--------|
| 10/04/2025 | 1.0 | Security Team | Initial creation |

## 📝 Additional Notes

Multiple layers of protection are recommended for ClickJacking defense. CSP frame-ancestors should be the primary defense, with X-Frame-Options as fallback for older browsers, and JavaScript protection as additional security measure.

---

**Status:** Open  
**Assigned to:** [Responsible name]  
**Due date:** 10/12/2025  
**Priority:** 3  
**Complexity:** Low

## 🚀 Quick Commands

```bash
# Create issue
gh issue create --title "🟠 SEC-007: ClickJacking Vulnerability" --body-file $(pwd)/project-docs/security-tasks/high/SEC-007-ClickJacking.md --label "security,high,SEC-007"

# Create branch
git checkout -b fix/security-sec007-ClickJacking

# Create PR
gh pr create --title "🐛 fix(security): SEC-007 - ClickJacking protection" --body "This PR implements the security fix for vulnerability SEC-007. Refer to the PR template for detailed testing instructions." --label "security,fix"

# Tests
bun run test:security
bun run test:unit
bun run build

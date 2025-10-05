import { NextRequest, NextResponse } from "next/server";
import { storeSpotifyConfig, getSpotifyConfig, isSessionValid } from "@/app/lib/session-manager";
import { logSecurityEvent, SecurityEventType, logError } from "@/app/lib/security-logger";
import crypto from 'crypto';

// Security headers
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'",
};

function addSecurityHeaders(response: NextResponse) {
  Object.entries(securityHeaders).forEach(([key, value]) => {
    response.headers.set(key, value);
  });
  return response;
}

// POST handler
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    
    let clientId: string, clientSecret: string, redirectUri: string;
    
    // Check if data is encrypted
    if (body.encryptedCredentials) {
      // Server-side decryption
      const { decryptAesKey } = await import('../crypto/public-key/route');
      
      let payload;
      try {
        // Safe base64 decoding using Buffer
        const jsonStr = Buffer.from(body.encryptedCredentials, 'base64').toString('utf8');
        payload = JSON.parse(jsonStr);
        
        // Validate payload structure
        if (!payload.encryptedAesKey || !payload.encryptedCredentials || !payload.iv) {
          throw new Error('Invalid payload structure');
        }
      } catch (decodeError) {
        logSecurityEvent(SecurityEventType.ENCRYPTION_ERROR, request, { error: 'Invalid base64 or payload' }, decodeError as Error);
        const response = NextResponse.json({ error: "Invalid encrypted credentials format" }, { status: 400 });
        return addSecurityHeaders(response);
      }
      
      // Decrypt AES key
      const aesKey = await decryptAesKey(payload.encryptedAesKey);
      
      // Decrypt data with AES
      const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(payload.iv, 'base64'));
      
      const encryptedBuffer = Buffer.from(payload.encryptedCredentials, 'base64');
      if (encryptedBuffer.length < 16) {
        throw new Error('Invalid encrypted data length');
      }
      const tag = encryptedBuffer.slice(-16);
      const ciphertext = encryptedBuffer.slice(0, -16);
      let decrypted = decipher.update(ciphertext);
      decipher.setAuthTag(tag);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      const credentials = JSON.parse(decrypted.toString());
      clientId = credentials.clientId;
      clientSecret = credentials.clientSecret;
      redirectUri = credentials.redirectUri;
    } else {
      // Fallback for non-encrypted mode (development)
      ({ clientId, clientSecret, redirectUri } = body);
    }

    // Validate input
    if (!clientId || !clientSecret || !redirectUri) {
      logSecurityEvent(SecurityEventType.INVALID_REQUEST, request, { missingFields: { clientId: !clientId, clientSecret: !clientSecret, redirectUri: !redirectUri } });
      const response = NextResponse.json({ error: "Client ID, Secret, and Redirect URI are required" }, { status: 400 });
      return addSecurityHeaders(response);
    }

    // Sanitize inputs
    const sanitizedClientId = clientId.trim();
    const sanitizedClientSecret = clientSecret.trim();
    const sanitizedRedirectUri = redirectUri.trim();

    if (!sanitizedClientId || !sanitizedClientSecret || !sanitizedRedirectUri) {
      logSecurityEvent(SecurityEventType.INVALID_REQUEST, request, { emptyFields: true });
      const response = NextResponse.json({ error: "Fields cannot be empty" }, { status: 400 });
      return addSecurityHeaders(response);
    }

    // Store in session with encryption
    await storeSpotifyConfig({
      clientId: sanitizedClientId,
      clientSecret: sanitizedClientSecret,
      redirectUri: sanitizedRedirectUri,
    });

    logSecurityEvent(SecurityEventType.CONFIG_STORED, request, { hasCredentials: true, encrypted: !!body.encryptedCredentials });

    const response = NextResponse.json({ success: true, encrypted: !!body.encryptedCredentials });
    return addSecurityHeaders(response);
  } catch (error) {
    logError("Error saving config", error as Error, request);
    logSecurityEvent(SecurityEventType.ENCRYPTION_ERROR, request, {}, error as Error);
    const response = NextResponse.json({ error: "Failed to save config" }, { status: 500 });
    return addSecurityHeaders(response);
  }
}

// GET handler
export async function GET(request: NextRequest) {
  try {
    const sessionValid = await isSessionValid();

    if (sessionValid) {
      // If session is valid, return session credentials without secret
      const config = await getSpotifyConfig();
      logSecurityEvent(SecurityEventType.CONFIG_RETRIEVED, request, { hasCredentials: !!config, source: 'session' });
      const response = NextResponse.json({
        clientId: config?.clientId || "",
        redirectUri: config?.redirectUri || "",
        hasCredentials: !!config,
        isConfigured: !!config?.clientId,
        // clientSecret REMOVED - never returned to client
      });
      return addSecurityHeaders(response);
    } else {
      // If no session credentials, check for environment variables as fallback
      const envClientId = process.env.SPOTIFY_CLIENT_ID;
      const envClientSecret = process.env.SPOTIFY_CLIENT_SECRET;

      if (envClientId && envClientSecret) {
        // Return environment variables (but don't include actual secrets in response for security)
        // We'll return a flag indicating env vars are available
        logSecurityEvent(SecurityEventType.CONFIG_RETRIEVED, request, { hasCredentials: true, source: 'env' });
        const response = NextResponse.json({
          clientId: envClientId,
          redirectUri: "",
          hasCredentials: true,
          isConfigured: true,
          source: 'env' // Indicate this came from environment variables
        });
        return addSecurityHeaders(response);
      } else {
        // No credentials available
        logSecurityEvent(SecurityEventType.CONFIG_RETRIEVED, request, { hasCredentials: false, source: 'none' });
        const response = NextResponse.json({
          clientId: "",
          redirectUri: "",
          hasCredentials: false,
          isConfigured: false
        });
        return addSecurityHeaders(response);
      }
    }
  } catch (error) {
    logError("Error reading config", error as Error, request);
    logSecurityEvent(SecurityEventType.DECRYPTION_ERROR, request, {}, error as Error);
    const response = NextResponse.json({ error: "Failed to read config" }, { status: 500 });
    return addSecurityHeaders(response);
  }
}
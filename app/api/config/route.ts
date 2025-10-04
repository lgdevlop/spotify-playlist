import { NextRequest, NextResponse } from "next/server";
import { storeSpotifyConfig, getSpotifyConfig, isSessionValid } from "@/app/lib/session-manager";
import { logSecurityEvent, SecurityEventType } from "@/app/lib/security-logger";

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
    const body = await request.json() as { clientId: string; clientSecret: string; redirectUri: string };
    const { clientId, clientSecret, redirectUri } = body;

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

    // Store in session
    await storeSpotifyConfig({
      clientId: sanitizedClientId,
      clientSecret: sanitizedClientSecret,
      redirectUri: sanitizedRedirectUri,
    });

    logSecurityEvent(SecurityEventType.CONFIG_STORED, request, { hasCredentials: true });

    const response = NextResponse.json({ success: true });
    return addSecurityHeaders(response);
  } catch (error) {
    console.error("Error saving config:", error);
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
      // If session is valid, return session credentials
      const config = await getSpotifyConfig();
      logSecurityEvent(SecurityEventType.CONFIG_RETRIEVED, request, { hasCredentials: !!config, source: 'session' });
      const response = NextResponse.json(config || { clientId: "", clientSecret: "", redirectUri: "" });
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
          clientSecret: "env_var_present", // Placeholder to indicate env var is available
          redirectUri: "",
          source: 'env' // Indicate this came from environment variables
        });
        return addSecurityHeaders(response);
      } else {
        // No credentials available
        logSecurityEvent(SecurityEventType.CONFIG_RETRIEVED, request, { hasCredentials: false, source: 'none' });
        const response = NextResponse.json({ clientId: "", clientSecret: "", redirectUri: "" });
        return addSecurityHeaders(response);
      }
    }
  } catch (error) {
    console.error("Error reading config:", error);
    logSecurityEvent(SecurityEventType.DECRYPTION_ERROR, request, {}, error as Error);
    const response = NextResponse.json({ error: "Failed to read config" }, { status: 500 });
    return addSecurityHeaders(response);
  }
}
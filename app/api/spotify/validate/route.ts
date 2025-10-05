import { NextResponse } from "next/server";
import type { ValidationResult } from "@/types";
import { logError } from "@/app/lib/security-logger";

interface SpotifyTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export async function POST() {
  try {
    // Uses stored credentials from session
    const { getSpotifyConfig } = await import('@/app/lib/session-manager');
    const credentials = await getSpotifyConfig();
    if (!credentials) {
      const result: ValidationResult = {
        valid: false,
        error: "No credentials configured. Please configure Spotify credentials first."
      };
      return NextResponse.json(result, { status: 400 });
    }
    
    // Validates using server-side credentials
    const authString = Buffer.from(`${credentials.clientId}:${credentials.clientSecret}`).toString('base64');

    const response = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authString}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
      }),
    });

    if (response.ok) {
      const data: SpotifyTokenResponse = await response.json();
      if (data.access_token) {
        const result: ValidationResult = { valid: true };
        return NextResponse.json(result);
      }
    }

    const result: ValidationResult = { valid: false, error: "Invalid Spotify credentials" };
    return NextResponse.json(result, { status: 401 });

  } catch (error) {
    logError("Error validating Spotify credentials", error as Error);
    const result: ValidationResult = { valid: false, error: "Failed to validate credentials" };
    return NextResponse.json(result, { status: 500 });
  }
}

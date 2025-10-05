import { NextRequest, NextResponse } from 'next/server';
import { getSpotifyConfig } from '@/app/lib/session-manager';

export async function POST(request: NextRequest) {
  try {
    const { refreshToken } = await request.json();
    
    if (!refreshToken) {
      return NextResponse.json({ error: "Refresh token is required" }, { status: 400 });
    }
    
    // Get stored credentials from session (not from client)
    const credentials = await getSpotifyConfig();
    if (!credentials) {
      return NextResponse.json({ error: "No credentials configured" }, { status: 400 });
    }
    
    // Use server-side credentials for refresh
    const response = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: {
        "Authorization": `Basic ${Buffer.from(`${credentials.clientId}:${credentials.clientSecret}`).toString('base64')}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken
      })
    });
    
    if (!response.ok) {
      return NextResponse.json({ error: "Token refresh failed" }, { status: response.status });
    }
    
    const tokens = await response.json();
    return NextResponse.json(tokens);
  } catch (error) {
    console.error("Error in token refresh:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
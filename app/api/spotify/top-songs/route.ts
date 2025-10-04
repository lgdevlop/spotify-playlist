import { authOptions } from "@/app/lib/auth";
import { getServerSession } from "next-auth/next";
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  try {
    // Recuperar credenciais da sessão para passar para authOptions
    const { getSpotifyConfig } = await import("@/app/lib/session-manager");
    const credentials = await getSpotifyConfig();
    
    const session = await getServerSession(authOptions(credentials ? {
      clientId: credentials.clientId,
      clientSecret: credentials.clientSecret
    } : undefined));

    if (!session?.accessToken) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const timeRange = searchParams.get("time_range") || "short_term";
    const limit = searchParams.get("limit") || "5";

    const response = await fetch(
      `https://api.spotify.com/v1/me/top/tracks?time_range=${timeRange}&limit=${limit}`,
      {
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Spotify API error: ${response.status}`);
    }

    const data = await response.json();

    return NextResponse.json(data);
  } catch (error) {
    console.error("Error fetching top songs:", error);
    return NextResponse.json(
      { error: "Failed to fetch top songs" },
      { status: 500 }
    );
  }
}

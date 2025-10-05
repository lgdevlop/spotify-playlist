import { NextRequest, NextResponse } from "next/server";
import { logError } from "@/app/lib/security-logger";

export async function GET(request: NextRequest) {
  try {
    const { getServerSession } = await import("next-auth/next");
    const { authOptions } = await import("@/app/lib/auth");
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
    const limit = parseInt(searchParams.get("limit") || "5");

    // Use SpotifyProxy for server-side API call
    const { SpotifyProxy } = await import("@/app/lib/spotify-proxy");
    const data = await SpotifyProxy.getTopTracks(session.accessToken, timeRange, limit);

    return NextResponse.json(data);
  } catch (error) {
    logError("Error fetching top songs", error as Error);
    return NextResponse.json(
      { error: "Failed to fetch top songs" },
      { status: 500 }
    );
  }
}

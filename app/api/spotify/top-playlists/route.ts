import { NextResponse } from "next/server";
import type { ApiResponse } from "@/types";
import { logError } from "@/app/lib/security-logger";

interface SpotifyPlaylist {
  id: string;
  name: string;
  description: string;
  images: Array<{ url: string }>;
  tracks: { total: number };
  owner: { display_name: string };
  public: boolean;
  external_urls: { spotify: string };
}

interface SpotifyPlaylistsResponse {
  items: SpotifyPlaylist[];
}

interface TransformedPlaylist {
  id: string;
  name: string;
  description: string;
  image: string | null;
  tracks: number;
  owner: string;
  public: boolean;
  external_urls: { spotify: string };
}

export async function GET() {
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
      const result: ApiResponse<TransformedPlaylist[]> = { success: false, error: "Unauthorized" };
      return NextResponse.json(result, { status: 401 });
    }

    // Use SpotifyProxy for server-side API call with automatic token refresh
    const { SpotifyProxy } = await import("@/app/lib/spotify-proxy");
    const data = await SpotifyProxy.getPlaylists(
      session.accessToken,
      5,
      session.spotifyId // Pass userId for automatic token refresh
    ) as SpotifyPlaylistsResponse;

    // Transform the data to include only necessary information
    const playlists: TransformedPlaylist[] = data.items.map((playlist: SpotifyPlaylist) => ({
      id: playlist.id,
      name: playlist.name,
      description: playlist.description,
      image: playlist.images?.[0]?.url || null,
      tracks: playlist.tracks?.total || 0,
      owner: playlist.owner?.display_name || "Unknown",
      public: playlist.public,
      external_urls: playlist.external_urls,
    }));

    const result: ApiResponse<TransformedPlaylist[]> = { success: true, data: playlists };
    return NextResponse.json(result);
  } catch (error) {
    logError("Error fetching playlists", error as Error);
    const result: ApiResponse<TransformedPlaylist[]> = { success: false, error: "Failed to fetch playlists" };
    return NextResponse.json(result, { status: 500 });
  }
}

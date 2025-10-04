import { getServerSession } from "next-auth/next";
import { NextResponse } from "next/server";
import { authOptions } from "@/app/lib/auth";
import type { ApiResponse } from "@/types";

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
    // Recuperar credenciais da sessão para passar para authOptions
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

    // Fetch user's playlists from Spotify
    const response = await fetch(
      "https://api.spotify.com/v1/me/playlists?limit=5",
      {
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Spotify API error: ${response.status}`);
    }

    const data: SpotifyPlaylistsResponse = await response.json();

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
    console.error("Error fetching playlists:", error);
    const result: ApiResponse<TransformedPlaylist[]> = { success: false, error: "Failed to fetch playlists" };
    return NextResponse.json(result, { status: 500 });
  }
}

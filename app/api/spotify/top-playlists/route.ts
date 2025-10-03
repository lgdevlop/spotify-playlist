import { getServerSession } from "next-auth/next";
import { NextResponse } from "next/server";
import { authOptions } from "@/app/lib/auth";

export async function GET() {
  try {
    const session = await getServerSession(authOptions());

    if (!session?.accessToken) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
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

    const data = await response.json();

    // Transform the data to include only necessary information
    const playlists = data.items.map(
      (playlist: {
        id: string;
        name: string;
        description: string;
        images: Array<{ url: string }>;
        tracks: { total: number };
        owner: { display_name: string };
        public: boolean;
        external_urls: { spotify: string };
      }) => ({
        id: playlist.id,
        name: playlist.name,
        description: playlist.description,
        image: playlist.images?.[0]?.url || null,
        tracks: playlist.tracks?.total || 0,
        owner: playlist.owner?.display_name || "Unknown",
        public: playlist.public,
        external_urls: playlist.external_urls,
      })
    );

    return NextResponse.json({ playlists });
  } catch (error) {
    console.error("Error fetching playlists:", error);
    return NextResponse.json(
      { error: "Failed to fetch playlists" },
      { status: 500 }
    );
  }
}

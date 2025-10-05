export class SpotifyProxy {
  static async makeAuthenticatedRequest(endpoint: string, accessToken: string): Promise<unknown> {
    const response = await fetch(`https://api.spotify.com/v1${endpoint}`, {
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      }
    });
    
    if (!response.ok) {
      throw new Error(`Spotify API error: ${response.status}`);
    }
    
    return response.json();
  }
  
  static async getTopTracks(accessToken: string, timeRange?: string, limit?: number) {
    return this.makeAuthenticatedRequest(`/me/top/tracks?time_range=${timeRange || 'short_term'}&limit=${limit || 5}`, accessToken);
  }
  
  static async getPlaylists(accessToken: string, limit?: number) {
    return this.makeAuthenticatedRequest(`/me/playlists?limit=${limit || 5}`, accessToken);
  }
}
// Core type definitions for the Spotify Playlist application

// Authentication configuration
export interface AuthConfig {
  clientId: string;
  clientSecret: string;
}

// Spotify configuration (re-exported for convenience)
export interface SpotifyConfig {
  clientId: string;
  clientSecret: string;
}

export interface ClientSpotifyConfig {
  clientId: string;
  redirectUri: string;
  hasCredentials: boolean;
  isConfigured: boolean;
}

// Generic API response wrapper
export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

// Validation result for credential checks
export interface ValidationResult {
  valid: boolean;
  error?: string;
}

// Configuration status for Spotify config hook
export interface ConfigStatus {
  isConfigured: boolean;
  isValid: boolean;
  isLoading: boolean;
  error: string | null;
  config: ClientSpotifyConfig | null;
}

// Security log entry (re-exported for convenience)
export interface SecurityLogEntry {
  timestamp: number;
  eventType: string;
  userAgent?: string;
  ip?: string;
  sessionId?: string;
  details?: Record<string, unknown>;
  error?: string;
}

// Spotify API types
export interface Track {
  id: string;
  name: string;
  artists: Array<{
    id: string;
    name: string;
  }>;
  album: {
    id: string;
    name: string;
    images: Array<{
      url: string;
      height: number;
      width: number;
    }>;
  };
  external_urls: {
    spotify: string;
  };
  duration_ms: number;
  popularity: number;
}

export interface TopSongsResponse {
  items: Track[];
}

// Playlist types
export interface Playlist {
  id: string;
  name: string;
  description: string;
  image: string | null;
  tracks: number;
  owner: string;
  public: boolean;
  external_urls: {
    spotify: string;
  };
}

// Re-export commonly used types from other modules
export { SecurityEventType } from '../app/lib/security-logger';
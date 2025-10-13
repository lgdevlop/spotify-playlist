// Mocks must be defined before imports that use them
import { test, expect, mock, describe, afterAll, vi, afterEach } from 'bun:test';
import { NextRequest } from 'next/server';

import { SpotifyProxy } from '@/app/lib/spotify-proxy';

interface SpotifyConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

afterAll(() => {
  mock.module("@/app/lib/spotify-proxy", () => ({
    SpotifyProxy
  }))
});

// afterEach(() => {
//   vi.restoreAllMocks()
// });

// Mock next/headers to avoid "cookies called outside request scope" error and for getServerSession
mockModule('next/headers', () => ({
  cookies: () => ({
    get: () => null,
    set: () => {},
    delete: () => {},
  }),
  headers: () => ({
    get: () => null,
    getAll: () => [],
    has: () => false,
    entries: function* () {},
    keys: function* () {},
    values: function* () {},
    append: () => {},
    delete: () => {},
    set: () => {},
  }),
}));

// Mock next-auth getServerSession to return mock session for top endpoints
mockModule('next-auth/next', () => ({
  getServerSession: async () => ({
    accessToken: 'mock_access_token',
  }),
}));

// Mock authOptions
mockModule('@/app/lib/auth', () => ({
  authOptions: () => ({}),
}));

// Mock session-manager functions (actual import path)
mockModule('@/app/lib/session-manager', () => ({
  storeSpotifyConfig: async (): Promise<void> => {
    // Mock successful storage
    return;
  },
  getSpotifyConfig: async (): Promise<SpotifyConfig | null> => null, // For validate, returns null to test no creds case
  isSessionValid: async (): Promise<boolean> => false,
}));

// Mock decryptAesKey to return valid 32-byte AES key
mockModule('@/app/api/crypto/public-key/route', () => ({
  decryptAesKey: async (): Promise<Buffer> => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return Buffer.from(bytes);
  },
}));

// Now import the routes after mocks
import { GET, POST as configPost } from '../../app/api/config/route';
import { POST as validatePost } from '../../app/api/spotify/validate/route';
import { mockModule } from '../mock-modules';

describe('SEC-001: Client Secret Exposure', () => {
  test('should not expose client secret in /api/config GET', async () => {
    const request = new NextRequest('http://localhost:3000/api/config');
    const response = await GET(request);
    const data = await response.json();
    
    expect(data.clientSecret).toBeUndefined();
    expect(data).not.toHaveProperty('clientSecret');
  });

  test('should handle invalid encrypted payload without exposing secrets', async () => {
    // Test invalid structure to hit the 400 branch in encryption handling
    const invalidPayload = { invalidField: 'invalid' };
    const mockBody = {
      encryptedCredentials: Buffer.from(JSON.stringify(invalidPayload)).toString('base64'),
    };

    const request = new NextRequest('http://localhost:3000/api/config', {
      method: 'POST',
      body: JSON.stringify(mockBody),
    });
    const response = await configPost(request);
    const data = await response.json();
    
    expect(response.status).toBe(400);
    expect(data).toHaveProperty('error');
    expect(data).not.toHaveProperty('clientSecret');
  });

  test('should not expose clientSecret in /api/config POST response with plain credentials (fallback)', async () => {
    const plainBody = {
      clientId: 'test',
      clientSecret: 'secret',
      redirectUri: 'http://localhost/callback',
    };

    const request = new NextRequest('http://localhost:3000/api/config', {
      method: 'POST',
      body: JSON.stringify(plainBody),
    });
    const response = await configPost(request);
    const data = await response.json();
    
    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(data).not.toHaveProperty('clientSecret');
    expect(data.encrypted).toBe(false);
  });

  test('should handle encrypted credentials processing error without exposing secrets', async () => {
    const plainCredentials = { clientId: 'test', clientSecret: 'secret', redirectUri: 'http://localhost/callback' };
    const jsonStr = JSON.stringify(plainCredentials);
    const fakeEncryptedData = Buffer.from(jsonStr + '0000000000000000', 'utf8'); // Plain + 16-byte tag
    const mockIv = Buffer.from('000000000000', 'utf8'); // 12 bytes IV
    const payload = {
      encryptedCredentials: fakeEncryptedData.toString('base64'),
      iv: mockIv.toString('base64'),
      encryptedAesKey: 'mock_encrypted_aes_key_base64',
    };
    const mockBody = {
      encryptedCredentials: Buffer.from(JSON.stringify(payload)).toString('base64'),
    };

    const request = new NextRequest('http://localhost:3000/api/config', {
      method: 'POST',
      body: JSON.stringify(mockBody),
    });
    const response = await configPost(request);
    const data = await response.json();
    
    expect(response.status).toBe(500);
    expect(data).toHaveProperty('error');
    expect(data).not.toHaveProperty('clientSecret');
  });

  test('should not expose clientSecret in any endpoint response', async () => {
    // Test /api/config GET
    const configRequest = new NextRequest('http://localhost:3000/api/config');
    const configResponse = await GET(configRequest);
    const configData = await configResponse.json();
    expect(configData.clientSecret).toBeUndefined();
    
    // Test /api/spotify/validate POST
    const validateResponse = await validatePost();
    const validateData = await validateResponse.json();
    expect(validateData).not.toHaveProperty('clientSecret');
  });

  test('should maintain user credential input functionality', async () => {
    // Test that /api/config POST succeeds without exposing or crashing
    const plainBody = {
      clientId: 'test',
      clientSecret: 'secret',
      redirectUri: 'http://localhost/callback',
    };

    const request = new NextRequest('http://localhost:3000/api/config', {
      method: 'POST',
      body: JSON.stringify(plainBody),
    });
    const response = await configPost(request);
    expect(response.status).toBe(200);
    expect(response.status).not.toBe(500);

    // Test /api/spotify/validate responds properly (400 if no creds, but endpoint functional)
    const validateResponse = await validatePost();
    expect(validateResponse.status).toBe(400);
    expect(validateResponse.status).not.toBe(500);
  });

  test('should handle decryption failure gracefully without exposing secrets', async () => {
    // Mock decryptAesKey to throw error (after structure validation)
    mockModule('@/app/api/crypto/public-key/route', () => ({
      decryptAesKey: async (): Promise<Buffer> => { throw new Error('Decryption failed'); },
    }));

    const plainCredentials = { clientId: 'test', clientSecret: 'secret', redirectUri: 'http://localhost/callback' };
    const jsonStr = JSON.stringify(plainCredentials);
    const fakeEncryptedData = Buffer.from(jsonStr + '0000000000000000', 'utf8');
    const mockIv = Buffer.from('000000000000', 'utf8');
    const payload = {
      encryptedCredentials: fakeEncryptedData.toString('base64'),
      iv: mockIv.toString('base64'),
      encryptedAesKey: 'mock_encrypted_aes_key_base64',
    };
    const mockBody = {
      encryptedCredentials: Buffer.from(JSON.stringify(payload)).toString('base64'),
    };

    const request = new NextRequest('http://localhost:3000/api/config', {
      method: 'POST',
      body: JSON.stringify(mockBody),
    });
    const response = await configPost(request);
    
    expect(response.status).toBe(500);
    const data = await response.json();
    expect(data).toHaveProperty('error');
    expect(data).not.toHaveProperty('clientSecret');
  });

  test('should not expose clientSecret in Spotify auth exchange proxy endpoint', async () => {
    const { POST: exchangePost } = await import('../../app/api/spotify/auth/exchange/route');

    // Mock getSpotifyConfig to return credentials
    mockModule('@/app/lib/session-manager', () => ({
      getSpotifyConfig: async () => ({
        clientId: 'test',
        clientSecret: 'secret',
        redirectUri: 'http://localhost/callback',
      }),
    }));

    // Mock fetch
    const mockFetch = async (): Promise<Response> => {
      return new Response(JSON.stringify({
        access_token: 'mock_access_token',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'mock_refresh_token',
      }), { status: 200 });
    };
    const originalFetch = global.fetch;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (global.fetch as any) = mockFetch;

    const request = new NextRequest('http://localhost:3000/api/spotify/auth/exchange', {
      method: 'POST',
      body: JSON.stringify({ code: 'mock_code', redirectUri: 'http://localhost/callback' }),
    });

    const response = await exchangePost(request);
    const data = await response.json();

    // Restore fetch
    global.fetch = originalFetch;

    expect(response.status).toBe(200);
    expect(data.access_token).toBe('mock_access_token');
    expect(data).not.toHaveProperty('clientSecret');
    expect(data).not.toHaveProperty('clientId');
  });

  test('should not expose clientSecret in Spotify auth refresh proxy endpoint', async () => {
    const { POST: refreshPost } = await import('../../app/api/spotify/auth/refresh/route');

    // Mock getSpotifyConfig to return credentials
    mockModule('@/app/lib/session-manager', () => ({
      getSpotifyConfig: async () => ({
        clientId: 'test',
        clientSecret: 'secret',
        redirectUri: 'http://localhost/callback',
      }),
    }));

    // Mock fetch
    const mockFetch = async (): Promise<Response> => {
      return new Response(JSON.stringify({
        access_token: 'mock_new_access_token',
        token_type: 'Bearer',
        expires_in: 3600,
      }), { status: 200 });
    };
    const originalFetch = global.fetch;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (global.fetch as any) = mockFetch;

    const request = new NextRequest('http://localhost:3000/api/spotify/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: 'mock_refresh_token' }),
    });

    const response = await refreshPost(request);
    const data = await response.json();

    global.fetch = originalFetch;

    expect(response.status).toBe(200);
    expect(data.access_token).toBe('mock_new_access_token');
    expect(data).not.toHaveProperty('clientSecret');
  });

  test('should not expose clientSecret in Spotify top playlists endpoint', async () => {
    const { GET: topPlaylistsGet } = await import('../../app/api/spotify/top-playlists/route');

    // Mock getSpotifyConfig to return credentials for authOptions
    mockModule('@/app/lib/session-manager', () => ({
      getSpotifyConfig: async () => ({
        clientId: 'test',
        clientSecret: 'secret',
        redirectUri: 'http://localhost/callback',
      }),
    }));

    // Mock SpotifyProxy
    mockModule('@/app/lib/spotify-proxy', () => ({
      SpotifyProxy: {
        getPlaylists: async () => ({
          items: [{ name: 'Mock Playlist', id: 'mock_id' }],
        }),
      },
    }));

    const response = await topPlaylistsGet();
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(Array.isArray(data.data)).toBe(true);
    expect(data).not.toHaveProperty('clientSecret');
  });

  test('should not expose clientSecret in Spotify top songs endpoint', async () => {
    const { GET: topSongsGet } = await import('../../app/api/spotify/top-songs/route');

    // Mock getSpotifyConfig to return credentials for authOptions
    mockModule('@/app/lib/session-manager', () => ({
      getSpotifyConfig: async () => ({
        clientId: 'test',
        clientSecret: 'secret',
        redirectUri: 'http://localhost/callback',
      }),
    }));

    // Mock SpotifyProxy
    mockModule('@/app/lib/spotify-proxy', () => ({
      SpotifyProxy: {
        makeAuthenticatedRequest: async () => ({ items: [] }),
        getTopTracks: async () => ({
          items: [{ name: 'Mock Song', id: 'mock_id' }],
        }),
        getPlaylists: async () => ({ items: [] }),
      },
    }));

    const request = new NextRequest('http://localhost:3000/api/spotify/top-songs');
    const response = await topSongsGet(request);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(Array.isArray(data.items)).toBe(true);
    expect(data).not.toHaveProperty('clientSecret');

    mock.clearAllMocks()
    mock.restore()
  });
});
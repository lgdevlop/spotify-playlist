import type { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { encrypt, decrypt } from './crypto';
import type { EncryptedData } from './crypto';

export interface SpotifyConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface EncryptedSpotifyConfig {
  clientId: string;
  clientSecret: EncryptedData;
  redirectUri: string;
}

export interface SessionData {
  spotifyConfig?: EncryptedSpotifyConfig;
  lastActivity: number;
  createdAt: number;
}

const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours
const INACTIVITY_TIMEOUT = 2 * 60 * 60 * 1000; // 2 hours
const COOKIE_NAME = 'spotify-session';

/**
 * Get session data from cookies with validation
 */
export async function getSessionData(): Promise<SessionData | null> {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get(COOKIE_NAME)?.value;

  if (!sessionCookie) {
    return null;
  }

  try {
    const session: SessionData = JSON.parse(sessionCookie);
    const now = Date.now();

    // Check session timeout
    if (now - session.createdAt > SESSION_TIMEOUT) {
      await clearSessionData();
      return null;
    }

    // Check inactivity timeout
    if (now - session.lastActivity > INACTIVITY_TIMEOUT) {
      await clearSessionData();
      return null;
    }

    // Update last activity
    session.lastActivity = now;
    await setSessionData(session);

    return session;
  } catch (error) {
    console.error('Failed to parse session data:', error);
    await clearSessionData();
    return null;
  }
}

/**
 * Set session data in cookies
 */
export async function setSessionData(data: SessionData): Promise<void> {
  const cookieStore = await cookies();

  cookieStore.set(COOKIE_NAME, JSON.stringify(data), {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: SESSION_TIMEOUT / 1000,
    path: '/',
  });
}

/**
 * Clear session data
 */
export async function clearSessionData(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(COOKIE_NAME);
}

/**
 * Store Spotify config in session (encrypting sensitive data)
 */
export async function storeSpotifyConfig(config: Omit<SpotifyConfig, 'clientSecret'> & { clientSecret: string }): Promise<void> {
  const encryptedSecret = encrypt(config.clientSecret);

  const spotifyConfig: EncryptedSpotifyConfig = {
    clientId: config.clientId,
    clientSecret: encryptedSecret,
    redirectUri: config.redirectUri,
  };

  const existing = await getSessionData();
  const now = Date.now();

  const newData: SessionData = {
    ...existing,
    spotifyConfig,
    lastActivity: now,
    createdAt: existing?.createdAt || now,
  };

  await setSessionData(newData);
}

/**
 * Retrieve Spotify config from session (decrypting sensitive data)
 */
export async function getSpotifyConfig(): Promise<SpotifyConfig | null> {
  const session = await getSessionData();
  
  if (!session?.spotifyConfig) {
    return null;
  }

  try {
    const decryptedSecret = decrypt(session.spotifyConfig.clientSecret);

    return {
      clientId: session.spotifyConfig.clientId,
      clientSecret: decryptedSecret,
      redirectUri: session.spotifyConfig.redirectUri,
    };
  } catch (error) {
    console.error('Failed to decrypt client secret:', error);
    return null;
  }
}

/**
 * Check if session is valid
 */
export async function isSessionValid(): Promise<boolean> {
  return (await getSessionData()) !== null;
}
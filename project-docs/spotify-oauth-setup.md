# Spotify OAuth Setup Guide

This document outlines the steps required to set up Spotify OAuth authentication for the AI Playlist Generator project.

## Prerequisites

- A Spotify Developer account (sign up at [Spotify for Developers](https://developer.spotify.com/))
- Node.js and npm/bun installed
- The project dependencies installed (`bun install` or `npm install`)

## Step 1: Create a Spotify Developer Application

1. Go to the [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
2. Click "Create an App"
3. Fill in the app name (e.g., "AI Playlist Generator") and description
4. Set the redirect URI to: `http://127.0.0.1:3000/api/auth/callback/spotify`
5. Note down the Client ID and Client Secret from the app settings

## Step 2: Configure Environment Variables

1. Copy `.env.sample` to `.env` in the project root
2. Fill in the following variables:
   - `SPOTIFY_CLIENT_ID`: Your Spotify app's Client ID
   - `SPOTIFY_CLIENT_SECRET`: Your Spotify app's Client Secret
   - `NEXTAUTH_URL`: `http://localhost:3000` (for local development)
   - `NEXTAUTH_SECRET`: Generate a secure random string (32 characters or more)

To generate a secure NEXTAUTH_SECRET, run:

```bash
openssl rand -base64 32
```

## Step 3: Update Spotify App Redirect URIs (if needed)

Ensure that `http://localhost:3000/api/auth/callback/spotify` is added to the "Redirect URIs" list in your Spotify app settings.

## Step 4: Run the Application

Start the development server:

```bash
bun run dev
```

## Step 5: Test the Authentication

1. Navigate to `http://localhost:3000/auth/signin`
2. Click "Sign in with Spotify"
3. Authorize the application in the Spotify popup
4. You should be redirected back and logged in

## How It Works

- **NextAuth Configuration**: The app uses NextAuth.js with the Spotify provider
- **Scopes**: The app requests the following scopes:
  - `user-read-email`
  - `user-read-private`
  - `user-top-read`
  - `user-read-recently-played`
  - `playlist-read-private`
  - `playlist-read-collaborative`
  - `playlist-modify-public`
  - `playlist-modify-private`
- **Token Management**: Access tokens are automatically refreshed when they expire
- **API Routes**: Protected routes use `getServerSession` to access the user's Spotify tokens

## Troubleshooting

- **"Invalid redirect URI" error**: Ensure the redirect URI is correctly set in your Spotify app
- **Authentication fails**: Check that all environment variables are set correctly
- **API calls fail**: Verify that the user has granted the necessary permissions

## Production Deployment

For production deployment:

- Update `NEXTAUTH_URL` to your production domain
- Add the production callback URL to your Spotify app's redirect URIs
- Ensure environment variables are set in your hosting platform

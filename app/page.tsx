"use client";

import { SessionProvider, signIn, signOut, useSession } from "next-auth/react";
import Image from "next/image";

export function Home() {
  const { data: session, status } = useSession();
  if (status === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-green-500 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="font-sans grid grid-rows-[20px_1fr_20px] items-center justify-items-center min-h-screen p-8 pb-20 gap-16 sm:p-20">
      <main className="flex flex-col gap-[32px] row-start-2 items-center sm:items-start">
        <Image
          src="/logo.svg"
          alt="AI Playlist Generator"
          width={180}
          height={38}
          priority
        />

        {session ? (
          <div className="text-center sm:text-left">
            <h1 className="text-2xl font-bold text-gray-900 mb-4">
              Welcome, {session.user?.name}!
            </h1>
            <p className="text-gray-600 mb-6">
              You&apos;re successfully connected to Spotify. Ready to generate
              your personalized playlist?
            </p>
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-4">
                <a
                  href="/top-songs"
                  className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded text-center"
                >
                  View Top Songs
                </a>
                <button
                  onClick={() => signOut()}
                  className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded"
                >
                  Sign Out
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center sm:text-left">
            <h1 className="text-2xl font-bold text-gray-900 mb-4">
              AI Playlist Generator
            </h1>
            <p className="text-gray-600 mb-6">
              Connect your Spotify account to generate personalized playlists
              using AI based on your musical taste.
            </p>
            <button
              onClick={() => signIn("spotify")}
              className="cursor-pointer bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded flex items-center gap-2"
            >
              <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.42 1.56-.299.421-1.02.599-1.559.3z" />
              </svg>
              Sign in with Spotify
            </button>
          </div>
        )}
      </main>
      <footer className="row-start-3 flex gap-[24px] flex-wrap items-center justify-center">
        <a
          className="flex items-center gap-2 hover:underline hover:underline-offset-4"
          href="https://github.com/lgdevlop/spotify-playlist"
          target="_blank"
          rel="noopener noreferrer"
        >
          <Image
            aria-hidden
            src="/globe.svg"
            alt="Globe icon"
            width={16}
            height={16}
          />
          Go to project github →
        </a>
      </footer>
    </div>
  );
}

export default function HomeWrapper() {
  return (
    <SessionProvider>
      <Home />
    </SessionProvider>
  );
}

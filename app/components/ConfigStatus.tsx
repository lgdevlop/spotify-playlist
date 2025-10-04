"use client";

import { useSpotifyConfig } from "@/app/hooks/useSpotifyConfig";

export default function ConfigStatus() {
  const { isConfigured, isValid, isLoading, redirectToConfig } = useSpotifyConfig();

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-gray-100 text-gray-600 text-sm">
        <div className="w-2 h-2 bg-gray-400 rounded-full animate-pulse"></div>
        <span>Checking configuration...</span>
      </div>
    );
  }

  if (!isConfigured) {
    return (
      <button
        onClick={redirectToConfig}
        className="flex items-center gap-2 px-3 py-1 rounded-full bg-red-100 text-red-700 text-sm hover:bg-red-200 transition-colors"
      >
        <div className="w-2 h-2 bg-red-500 rounded-full"></div>
        <span>Spotify not configured</span>
      </button>
    );
  }

  if (!isValid) {
    return (
      <button
        onClick={redirectToConfig}
        className="flex items-center gap-2 px-3 py-1 rounded-full bg-yellow-100 text-yellow-700 text-sm hover:bg-yellow-200 transition-colors"
      >
        <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
        <span>Invalid credentials</span>
      </button>
    );
  }

  return (
    <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-green-100 text-green-700 text-sm">
      <div className="w-2 h-2 bg-green-500 rounded-full"></div>
      <span>Spotify configured</span>
    </div>
  );
}
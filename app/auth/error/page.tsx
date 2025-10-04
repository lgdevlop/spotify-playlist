"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useSpotifyConfig } from "../../hooks/useSpotifyConfig";

export default function AuthError() {
  const router = useRouter();
  const { shouldRedirectToConfig, redirectToConfig } = useSpotifyConfig();

  useEffect(() => {
    // If credentials are not configured, redirect to config page
    if (shouldRedirectToConfig) {
      redirectToConfig();
    }
  }, [shouldRedirectToConfig, redirectToConfig]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Authentication Error
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            There was an error with Spotify authentication. This might be due to missing or invalid credentials.
          </p>
        </div>
        <div className="mt-8 space-y-6">
          <div className="bg-red-50 border border-red-200 rounded-md p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <p className="text-sm text-red-700">
                  Spotify authentication failed. Please check your credentials and try again.
                </p>
              </div>
            </div>
          </div>
          <div className="space-y-4">
            <button
              onClick={() => router.push("/config")}
              className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
            >
              Configure Spotify Credentials
            </button>
            <button
              onClick={() => router.push("/auth/signin")}
              className="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
            >
              Try Again
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useSpotifyConfig } from "../hooks/useSpotifyConfig";

export default function Config() {
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [redirectUri, setRedirectUri] = useState("");
  const [isValidating, setIsValidating] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const router = useRouter();
  const { updateStatus } = useSpotifyConfig();

  useEffect(() => {
    // Load from server
    const loadConfig = async () => {
      try {
        const response = await fetch("/api/config");
        if (response.ok) {
          const config = await response.json() as { clientId: string; clientSecret: string; redirectUri: string };
          setClientId(config.clientId || "");
          setClientSecret(config.clientSecret || "");
          setRedirectUri(config.redirectUri || "");
        }
      } catch (error) {
        console.error("Error loading config:", error);
      } finally {
        setIsLoading(false);
      }
    };

    loadConfig();
  }, []);

  const handleSave = async () => {
    if (!clientId || !clientSecret || !redirectUri) {
      alert("Please fill in all fields.");
      return;
    }

    setIsValidating(true);
    setValidationError(null);

    try {
      // First, validate the credentials
      const validationResponse = await fetch("/api/spotify/validate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ clientId, clientSecret }),
      });

      const validationResult = await validationResponse.json() as { valid: boolean; error?: string };

      if (!validationResult.valid) {
        setValidationError(validationResult.error || "Invalid Spotify credentials");
        setIsValidating(false);
        return;
      }

      // If validation passed, save to server
      const response = await fetch("/api/config", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ clientId, clientSecret, redirectUri }),
      });

      if (!response.ok) {
        throw new Error("Failed to save credentials");
      }

      // Update the config status
      await updateStatus();

      // Show success message and redirect
      setSuccessMessage("Credentials saved and validated successfully! Redirecting to sign in...");
      setTimeout(() => {
        router.push("/auth/signin");
      }, 2000);
    } catch (error) {
      console.error("Error saving credentials:", error);
      setValidationError("Failed to save credentials. Please try again.");
    } finally {
      setIsValidating(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Spotify Configuration
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Enter your Spotify app credentials. These will be validated and saved for authentication.
          </p>
        </div>
        <div className="mt-8 space-y-6">
          {validationError && (
            <div className="bg-red-50 border border-red-200 rounded-md p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <p className="text-sm text-red-700">{validationError}</p>
                </div>
              </div>
            </div>
          )}

          {successMessage && (
            <div className="bg-green-50 border border-green-200 rounded-md p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <p className="text-sm text-green-700">{successMessage}</p>
                </div>
              </div>
            </div>
          )}

          <div>
            <label htmlFor="clientId" className="block text-sm font-medium text-gray-700">
              Client ID
            </label>
            <input
              id="clientId"
              type="text"
              value={clientId}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setClientId(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500"
              placeholder="Your Spotify Client ID"
            />
          </div>
          <div>
            <label htmlFor="clientSecret" className="block text-sm font-medium text-gray-700">
              Client Secret
            </label>
            <input
              id="clientSecret"
              type="password"
              value={clientSecret}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setClientSecret(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500"
              placeholder="Your Spotify Client Secret"
            />
          </div>
          <div>
            <label htmlFor="redirectUri" className="block text-sm font-medium text-gray-700">
              Redirect URI
            </label>
            <input
              id="redirectUri"
              type="text"
              value={redirectUri}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setRedirectUri(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500"
              placeholder="http://localhost:3000/api/auth/callback/spotify"
            />
          </div>
          <div>
            <button
              onClick={handleSave}
              disabled={isValidating}
              className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isValidating ? (
                <div className="flex items-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Validating...
                </div>
              ) : (
                "Save & Validate Credentials"
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import type { ConfigStatus } from "@/types";
import type { ClientSpotifyConfig } from "@/types";
import { logError } from "@/app/lib/security-logger";

export function useSpotifyConfig() {
  const router = useRouter();
  const [status, setStatus] = useState<ConfigStatus>({
    isConfigured: false,
    isValid: false,
    isLoading: true,
    error: null,
    config: null,
  });


  // Validar credenciais com a API do Spotify (server-side only)
  const validateCredentials = useCallback(async (): Promise<boolean> => {
    try {
      const response = await fetch("/api/spotify/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}) // Empty - uses stored credentials
      });
      
      return (await response.json()).valid;
    } catch (error) {
      logError("Error validating credentials", error as Error);
      return false;
    }
  }, []);

  // Atualizar status da configuração
  const updateStatus = useCallback(async () => {
    setStatus((prev: ConfigStatus) => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await fetch("/api/config");
      if (!response.ok) {
        throw new Error("Failed to fetch config");
      }

      const rawConfig = await response.json();

      if (!rawConfig.clientId || !rawConfig.hasCredentials) {
        setStatus({
          isConfigured: false,
          isValid: false,
          isLoading: false,
          error: null,
          config: null,
        });
        return;
      }

      // Validate using server-side credentials
      const isValid = await validateCredentials();

      // Create config object without secret
      const config: ClientSpotifyConfig = {
        clientId: rawConfig.clientId || "",
        redirectUri: rawConfig.redirectUri || "",
        hasCredentials: rawConfig.hasCredentials,
        isConfigured: rawConfig.isConfigured
      };

      setStatus({
        isConfigured: rawConfig.isConfigured,
        isValid,
        isLoading: false,
        error: isValid ? null : "Invalid Spotify credentials",
        config,
      });
    } catch (error) {
      setStatus({
        isConfigured: false,
        isValid: false,
        isLoading: false,
        error: error instanceof Error ? error.message : "Unknown error",
        config: null,
      });
    }
  }, [validateCredentials]);

  // Redirecionar para configuração se necessário
  const redirectToConfig = useCallback(() => {
    router.push("/config");
  }, [router]);

  // Redirecionar para signin se configurado
  const redirectToSignin = useCallback(() => {
    router.push("/auth/signin");
  }, [router]);

  // Efeito para verificar configuração na montagem
  useEffect(() => {
    updateStatus();
  }, [updateStatus]);

  // Efeito para redirecionar automaticamente se verificação completa falhar
  useEffect(() => {
    if (!status.isLoading && !status.isConfigured) {
      redirectToConfig();
    }
  }, [status.isLoading, status.isConfigured, redirectToConfig]);

  return {
    ...status,
    updateStatus,
    redirectToConfig,
    redirectToSignin,
    // Método para verificar se deve redirecionar
    shouldRedirectToConfig: !status.isConfigured && !status.isLoading,
    // Método para verificar se pode prosseguir com autenticação
    canProceedWithAuth: status.isConfigured && status.isValid && !status.isLoading,
  };
}
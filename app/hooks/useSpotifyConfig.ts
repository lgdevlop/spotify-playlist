"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import type { SpotifyConfig, ConfigStatus, ValidationResult } from "@/types";

export function useSpotifyConfig() {
  const router = useRouter();
  const [status, setStatus] = useState<ConfigStatus>({
    isConfigured: false,
    isValid: false,
    isLoading: true,
    error: null,
    config: null,
  });


  // Validar credenciais com a API do Spotify
  const validateCredentials = useCallback(async (config: SpotifyConfig & { source?: string }): Promise<boolean> => {
    try {
      const requestBody = {
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        useEnvVars: config.source === 'env' // Use env vars for validation when source is 'env'
      };

      const response = await fetch("/api/spotify/validate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        return false;
      }

      const result: ValidationResult = await response.json();
      return result.valid === true;
    } catch (error) {
      console.error("Error validating credentials:", error);
      return false;
    }
  }, []);

  // Atualizar status da configuração
  const updateStatus = useCallback(async () => {
    setStatus((prev: ConfigStatus) => ({ ...prev, isLoading: true, error: null }));

    try {
      // Get raw config response to preserve source information
      const response = await fetch("/api/config");
      if (!response.ok) {
        throw new Error("Failed to fetch config");
      }

      const rawConfig = await response.json();

      if (!rawConfig.clientId || !rawConfig.clientSecret || rawConfig.clientSecret === "") {
        setStatus({
          isConfigured: false,
          isValid: false,
          isLoading: false,
          error: null,
          config: null,
        });
        return;
      }

      // Create config object for validation
      const configForValidation = {
        clientId: rawConfig.clientId,
        clientSecret: rawConfig.clientSecret,
        source: rawConfig.source
      };

      const isValid = await validateCredentials(configForValidation);

      // Create config object for status (without source)
      const config: SpotifyConfig = {
        clientId: rawConfig.clientId,
        clientSecret: rawConfig.clientSecret
      };

      setStatus({
        isConfigured: true,
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
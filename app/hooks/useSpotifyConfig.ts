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

  // Verificar se as credenciais estão configuradas
  const checkConfiguration = useCallback(async (): Promise<SpotifyConfig | null> => {
    try {
      const response = await fetch("/api/config");
      if (!response.ok) {
        throw new Error("Failed to fetch config");
      }

      const config: SpotifyConfig = await response.json();

      if (config.clientId && config.clientSecret) {
        return config;
      }

      return null;
    } catch (error) {
      console.error("Error checking configuration:", error);
      return null;
    }
  }, []);

  // Validar credenciais com a API do Spotify
  const validateCredentials = useCallback(async (config: SpotifyConfig): Promise<boolean> => {
    try {
      const response = await fetch("/api/spotify/validate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(config),
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
      const config = await checkConfiguration();

      if (!config) {
        setStatus({
          isConfigured: false,
          isValid: false,
          isLoading: false,
          error: null,
          config: null,
        });
        return;
      }

      const isValid = await validateCredentials(config);

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
  }, [checkConfiguration, validateCredentials]);

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
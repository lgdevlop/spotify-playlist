import { NextRequest, NextResponse } from "next/server";
import type { SpotifyConfig, ValidationResult } from "@/types";

interface SpotifyTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export async function POST(request: NextRequest) {
  try {
    const body: SpotifyConfig = await request.json();
    const { clientId, clientSecret } = body;

    if (!clientId || !clientSecret) {
      const result: ValidationResult = { valid: false, error: "Client ID and Client Secret are required" };
      return NextResponse.json(result, { status: 400 });
    }

    // Testar as credenciais fazendo uma chamada para o endpoint de token do Spotify
    // Usamos o fluxo client_credentials para testar se as credenciais são válidas
    const authString = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const response = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authString}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
      }),
    });

    if (response.ok) {
      const data: SpotifyTokenResponse = await response.json();
      if (data.access_token) {
        const result: ValidationResult = { valid: true };
        return NextResponse.json(result);
      }
    }

    // Se chegou aqui, as credenciais são inválidas
    const result: ValidationResult = { valid: false, error: "Invalid Spotify credentials" };
    return NextResponse.json(result, { status: 401 });

  } catch (error) {
    console.error("Error validating Spotify credentials:", error);
    const result: ValidationResult = { valid: false, error: "Failed to validate credentials" };
    return NextResponse.json(result, { status: 500 });
  }
}

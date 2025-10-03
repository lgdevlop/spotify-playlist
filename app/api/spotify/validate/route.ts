import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  try {
    const { clientId, clientSecret } = await request.json();

    if (!clientId || !clientSecret) {
      return NextResponse.json(
        { valid: false, error: "Client ID and Client Secret are required" },
        { status: 400 }
      );
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
      const data = await response.json();
      if (data.access_token) {
        return NextResponse.json({ valid: true });
      }
    }

    // Se chegou aqui, as credenciais são inválidas
    return NextResponse.json(
      { valid: false, error: "Invalid Spotify credentials" },
      { status: 401 }
    );

  } catch (error) {
    console.error("Error validating Spotify credentials:", error);
    return NextResponse.json(
      { valid: false, error: "Failed to validate credentials" },
      { status: 500 }
    );
  }
}

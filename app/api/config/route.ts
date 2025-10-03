import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";

const configFilePath = path.join(process.cwd(), "spotify-config.json");

export async function POST(request: NextRequest) {
  try {
    const { clientId, clientSecret } = await request.json();

    if (!clientId || !clientSecret) {
      return NextResponse.json({ error: "Client ID and Secret are required" }, { status: 400 });
    }

    const config = { clientId, clientSecret };
    fs.writeFileSync(configFilePath, JSON.stringify(config, null, 2));

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Error saving config:", error);
    return NextResponse.json({ error: "Failed to save config" }, { status: 500 });
  }
}

export async function GET() {
  try {
    if (fs.existsSync(configFilePath)) {
      const config = JSON.parse(fs.readFileSync(configFilePath, "utf-8"));
      return NextResponse.json(config);
    } else {
      return NextResponse.json({ clientId: "", clientSecret: "" });
    }
  } catch (error) {
    console.error("Error reading config:", error);
    return NextResponse.json({ error: "Failed to read config" }, { status: 500 });
  }
}
import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AI Playlist Generator",
  description:
    "Generate personalized Spotify playlists using AI based on your musical taste",
  icons: {
    icon: [
      { url: "/icon.svg", type: "image/svg+xml" },
      { url: "/favicon.svg", type: "image/svg+xml" },
    ],
    apple: "/icon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <header className="w-full flex items-center justify-between py-4 px-6 border-b border-gray-200 mb-8">
          <div className="flex items-center gap-2">
            <img
              src="/logo.svg"
              alt="AI Playlist Generator Logo"
              width={32}
              height={32}
            />
            <span className="font-bold text-lg tracking-tight">
              AI Playlist Generator
            </span>
          </div>
          <nav>
            <a
              href="https://github.com/lgdevlop/spotify-playlist"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm font-mono hover:underline underline-offset-4"
            >
              GitHub
            </a>
          </nav>
        </header>
        {children}
        <footer className="w-full flex items-center justify-center py-6 border-t border-gray-200 mt-12">
          <a
            className="flex items-center gap-2 text-sm font-mono hover:underline underline-offset-4"
            href="https://github.com/lgdevlop/spotify-playlist"
            target="_blank"
            rel="noopener noreferrer"
          >
            <img
              src="/globe.svg"
              alt="Globe icon"
              width={16}
              height={16}
              aria-hidden="true"
            />
            Go to project github →
          </a>
        </footer>
      </body>
    </html>
  );
}

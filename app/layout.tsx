import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Image from "next/image";
import Link from "next/link";
import Providers from "./components/Providers";
import Header from "./components/Header";
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
        <Providers>
          <Header />
          {children}
          <footer className="w-full flex items-center gap-5 justify-center py-6 border-t border-gray-200 mt-12">
            <Link
              className="flex items-center gap-2 hover:underline hover:underline-offset-4"
              href="/about"
            >
              <Image
                aria-hidden
                src="/file.svg"
                alt="Document icon"
                width={16}
                height={16}
              />
              About Us
            </Link>
            <a
              className="flex items-center gap-2 text-sm font-mono hover:underline underline-offset-4"
              href="https://github.com/lgdevlop/spotify-playlist"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Image
                src="/globe.svg"
                alt="Globe icon"
                width={16}
                height={16}
                aria-hidden="true"
              />
              Github
            </a>
          </footer>
        </Providers>
      </body>
    </html>
  );
}

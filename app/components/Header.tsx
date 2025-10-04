"use client";

import { useSession, signOut } from "next-auth/react";
import Image from "next/image";
import Link from "next/link";
import ConfigStatus from "./ConfigStatus";

export default function Header() {
  const { data: session } = useSession();

  return (
    <header className="w-full flex items-center justify-between py-4 px-6 border-b border-gray-200 mb-8">
      <div className="flex items-center gap-2">
        <Image
          src="/logo.svg"
          alt="AI Playlist Generator Logo"
          width={32}
          height={32}
        />
        <span className="font-bold text-lg tracking-tight">
          AI Playlist Generator
        </span>
      </div>
      <div className="flex items-center gap-4">
        <ConfigStatus />
        <Link
          href="/config"
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          Config
        </Link>
        {session && (
          <button
            onClick={() => signOut({ callbackUrl: "/" })}
            className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
          >
            Logout
          </button>
        )}
      </div>
    </header>
  );
}
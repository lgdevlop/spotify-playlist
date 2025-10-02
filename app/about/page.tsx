export default function AboutPage() {
  return (
    <div className="font-sans grid grid-rows-[20px_1fr_20px] items-center justify-items-center min-h-screen p-8 pb-20 gap-16 sm:p-20">
      <main className="flex flex-col gap-[16px] row-start-2 items-center sm:items-start max-w-prose">
        <h1 className="text-3xl font-semibold tracking-tight">About Us</h1>
        <p className="text-base text-gray-700">
          AI Playlist Generator helps you create personalized Spotify playlists
          using AI. We analyze your music preferences to curate tracks that
          match your taste and mood.
        </p>
        <p className="text-base text-gray-700">
          This is an open-source project. Contributions, feedback, and ideas are
          welcome!
        </p>
      </main>
    </div>
  );
}

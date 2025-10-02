import { render, screen } from "@testing-library/react";
import { describe, expect, it, mock } from "bun:test";
import Home from "./page";

// Mock NextAuth
const mockUseSession = mock(() => ({
  data: null,
  status: "unauthenticated",
}));

const mockSignIn = mock(() => {});

// Mock the next-auth/react module
mock.module("next-auth/react", () => ({
  useSession: mockUseSession,
  signIn: mockSignIn,
  SessionProvider: ({ children }: { children: React.ReactNode }) => children,
}));

describe("Home Page", () => {
  it("renders the main content when not authenticated", () => {
    // Mock unauthenticated state
    mockUseSession.mockReturnValue({
      data: null,
      status: "unauthenticated",
    });

    render(<Home />);

    // Check if the main heading is present
    const heading = screen.getByText("AI Playlist Generator");
    expect(heading).toBeDefined();

    // Check if the sign in button is present
    const signInButton = screen.getByText("Sign in with Spotify");
    expect(signInButton).toBeDefined();
  });

  it("renders the main content when authenticated", () => {
    // Mock authenticated state
    mockUseSession.mockReturnValue({
      data: {
        user: {
          name: "Test User",
          email: "test@example.com",
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any,
      status: "authenticated",
    });

    render(<Home />);

    // Check if the welcome message is present
    const welcomeMessage = screen.getByText("Welcome, Test User!");
    expect(welcomeMessage).toBeDefined();

    // Check if the playlist link is present
    const playlistLink = screen.getByText("View My Top 5 Playlists");
    expect(playlistLink).toBeDefined();
  });

  it("renders loading state", () => {
    // Mock loading state
    mockUseSession.mockReturnValue({
      data: null,
      status: "loading",
    });

    render(<Home />);

    // Check if the loading text is present
    const loadingText = screen.getByText("Loading...");
    expect(loadingText).toBeDefined();
  });
});

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "bun:test";
import Home from "./page";

describe("Home Page", () => {
  it("renders the main content", () => {
    render(<Home />);

    // Check if the Next.js logo is present
    const logo = screen.getByText("Loading...");
    expect(logo).toBeDefined();
  });
});

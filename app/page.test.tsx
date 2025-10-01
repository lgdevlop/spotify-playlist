import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "bun:test";
import Home from "./page";

describe("Home Page", () => {
  it("renders the main content", () => {
    render(<Home />);

    // Check if the Next.js logo is present
    const logo = screen.getByAltText("Next.js logo");
    expect(logo).toBeDefined();
  });

  it("renders the project links", () => {
    render(<Home />);

    // Check that page instructional items are present
    expect(screen.getByText("Learn more about the project.")).toBeDefined();
    expect(screen.getByText("Try help the project grow.")).toBeDefined();
  });
});

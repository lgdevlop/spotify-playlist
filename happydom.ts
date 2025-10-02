import { GlobalRegistrator } from "@happy-dom/global-registrator";

GlobalRegistrator.register();

// Ensure a valid base URL for components that rely on URL parsing (e.g., next/image)
// Happy DOM exposes a runtime API to set the current document URL.
// Some libraries use `new URL(path)` which requires a base URL to avoid "Invalid URL" errors.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).window?.happyDOM?.setURL?.("http://localhost/");

import { afterEach, afterAll, mock, vi } from 'bun:test';

// Store original console methods to restore them later
const originalConsole = {
  log: console.log,
  error: console.error,
  warn: console.warn,
  info: console.info,
  debug: console.debug,
};

console.log = () => {};
console.warn = () => {};
console.error = () => {};
// console.info = () => {};

// Function to restore console methods
function restoreConsole(): void {
  console.log = originalConsole.log;
  console.error = originalConsole.error;
  console.warn = originalConsole.warn;
  console.info = originalConsole.info;
  console.debug = originalConsole.debug;
}

// Make the function available globally for tests
// Use proper type annotation to avoid TypeScript error
(globalThis as Record<string, unknown>).restoreConsole = restoreConsole;

afterEach(() => {
  mock.restore()
  // restoreConsole()
  vi.restoreAllMocks()
});

afterAll(() => {
  vi.restoreAllMocks()
});

/* eslint-disable prefer-const */
import { mock } from "bun:test";

/**
 *
 * @param modulePath - the path starting from this files' path.
 * @param renderMocks - function to generate mocks (by their named or default exports)
 * @returns an object
 */
export const mockModule = async (
  modulePath: string,
  renderMocks: () => Record<string, unknown>,
) => {
  let original = {
    ...(await import(modulePath)),
  };
  let mocks = renderMocks();
  let result = {
    ...original,
    ...mocks,
  };
  mock.module(modulePath, () => result);
  return {
    [Symbol.dispose]: () => {
      mock.module(modulePath, () => original);
    },
  };
};
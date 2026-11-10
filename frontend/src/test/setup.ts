import "@testing-library/jest-dom/vitest";

// jsdom does not implement ResizeObserver, which Recharts' ResponsiveContainer needs.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;

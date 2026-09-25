import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: { "@": fileURLToPath(new URL("./", import.meta.url)) },
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // Fixed zone so local-time formatting is deterministic (and has DST).
    env: { TZ: "Europe/Paris" },
    // Parsing the 13 MB fixture set takes a few seconds on first load.
    testTimeout: 30_000,
  },
});

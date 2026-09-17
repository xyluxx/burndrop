import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    coverage: {
      provider: "v8",
      include: ["src/crypto.ts", "src/link.ts", "src/base64.ts", "src/state.ts", "src/api.ts"],
      thresholds: {
        "src/crypto.ts": { statements: 100, branches: 100, functions: 100, lines: 100 },
        "src/link.ts": { statements: 100, branches: 100, functions: 100, lines: 100 },
        "src/base64.ts": { statements: 100, branches: 100, functions: 100, lines: 100 },
        "src/state.ts": { statements: 95, branches: 90, functions: 95, lines: 95 },
      },
      reporter: ["text", "html"],
    },
  },
});

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    // zod v4 ESM/CJS interop is flaky under vitest's default externalization;
    // inlining keeps `import { z } from "zod"` consistent across test graphs.
    server: { deps: { inline: ["zod"] } },
  },
});

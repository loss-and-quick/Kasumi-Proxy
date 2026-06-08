import { defineConfig } from "vitest/config";
import { readModuleVersion } from "./scripts/module-version";

export default defineConfig({
  // Mirror the Vite build's __MODULE_VERSION__ inject so code under test resolves it.
  define: {
    __MODULE_VERSION__: JSON.stringify(readModuleVersion()),
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    // zod v4 ESM/CJS interop is flaky under vitest's default externalization;
    // inlining keeps `import { z } from "zod"` consistent across test graphs.
    server: { deps: { inline: ["zod"] } },
  },
});

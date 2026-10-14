import { fileURLToPath } from 'node:url';
import { defineConfig, normalizePath } from 'vite';
const generatedWork = normalizePath(fileURLToPath(new URL('./work', import.meta.url)));
export default defineConfig({
  server: {
    // Retained evidence and database binaries are not frontend source files.
    watch: { ignored: [generatedWork, `${generatedWork}/**`] },
  },
});

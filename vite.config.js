import { defineConfig } from "vite";

export default defineConfig({
  base: "/bitterbake/",
  server: {
    port: 3000
  },
  build: {
    outDir: "dist",
    emptyOutDir: true
  }
});

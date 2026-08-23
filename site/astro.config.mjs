import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://shadowpath.coriolislabs.ca",
  output: "static",
  build: {
    format: "directory",
    assets: "assets",
  },
  vite: {
    build: {
      assetsInlineLimit: 0,
    },
  },
});

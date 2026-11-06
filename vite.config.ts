import { defineConfig } from "vite-plus";
import vue from "@vitejs/plugin-vue";
import { voidPlugin } from "void";
import { fileURLToPath } from "node:url";
import { serviceWorkerPlugin } from "./build/sw-plugin";

export default defineConfig({
  plugins: [
    voidPlugin(),
    vue(),
    serviceWorkerPlugin({ template: fileURLToPath(new URL("./build/sw-template.js", import.meta.url)) }),
  ],
  fmt: {
    printWidth: 120,
    quoteProps: "consistent",
    ignorePatterns: ["docs/BRIEF.md", "test/fixtures/**", "build/sw-template.js"],
  },
  test: {
    include: ["test/**/*.test.ts"],
  },
});

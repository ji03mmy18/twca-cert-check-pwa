import { defineConfig } from "vite-plus";
import vue from "@vitejs/plugin-vue";
import { voidPlugin } from "void";

export default defineConfig({
  plugins: [voidPlugin(), vue()],
  fmt: {
    printWidth: 120,
    quoteProps: "consistent",
    ignorePatterns: ["BRIEF.md", "test/fixtures/**"],
  },
  test: {
    include: ["test/**/*.test.ts"],
  },
});

import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { voidPlugin } from "void";

export default defineConfig({
  plugins: [voidPlugin(), vue()],
});

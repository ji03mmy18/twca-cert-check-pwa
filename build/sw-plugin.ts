/**
 * 產生 Service Worker 的 Vite plugin。
 *
 * 為什麼不用 vite-plugin-pwa：Void 的多環境建置（client + worker）會讓 vite-plugin-pwa
 * 在 closeBundle 寫出的 sw.js 不會出現在部署目錄中。這裡改成在 client 環境的
 * generateBundle 階段把 sw.js 當成一般 asset 輸出，由 Void 一起部署。
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Plugin } from "vite";

function walk(dir: string): string[] {
  let out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (name.startsWith(".")) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out = out.concat(walk(p));
    else out.push(p);
  }
  return out;
}

const PRECACHE_EXT = /\.(?:html|js|css|svg|png|webmanifest|ico|woff2?)$/;

export function serviceWorkerPlugin(options: { template: string }): Plugin {
  let publicDir = "";
  return {
    name: "twca:service-worker",
    apply: "build",
    configResolved(config) {
      publicDir = config.publicDir;
    },
    generateBundle(_opts, bundle) {
      // 只在瀏覽器端（client）環境輸出
      const envName = (this as unknown as { environment?: { name: string } }).environment?.name;
      if (envName && envName !== "client") return;

      const hash = createHash("sha256");
      const files = new Set<string>();
      for (const [fileName, chunk] of Object.entries(bundle)) {
        if (!PRECACHE_EXT.test(fileName) || fileName.startsWith(".vite/")) continue;
        files.add(fileName);
        hash.update(fileName);
        hash.update(chunk.type === "chunk" ? chunk.code : chunk.source);
      }
      for (const abs of walk(publicDir)) {
        const rel = relative(publicDir, abs).split("\\").join("/");
        if (!PRECACHE_EXT.test(rel)) continue;
        files.add(rel);
        hash.update(rel);
        hash.update(readFileSync(abs));
      }
      const urls = [
        "/",
        ...[...files]
          .sort()
          .map((f) => `/${f}`)
          .filter((u) => u !== "/index.html"),
      ];
      const version = hash.digest("hex").slice(0, 12);
      const source = readFileSync(options.template, "utf8")
        .replace("__PRECACHE_URLS__", JSON.stringify(urls))
        .replace("__CACHE_VERSION__", JSON.stringify(version));
      this.emitFile({ type: "asset", fileName: "sw.js", source });
    },
  };
}

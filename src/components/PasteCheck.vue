<script setup lang="ts">
import { ref } from "vue";
import { evaluate } from "../../shared/evaluate";
import { extractFromFile, extractPemCertificates } from "../../shared/pem";
import { sha256Hex } from "../../shared/x509";
import type { CardData } from "../types";
import ResultCard from "./ResultCard.vue";

const text = ref("");
const card = ref<CardData | null>(null);
const fileNames = ref<string[]>([]);
const fileDers = ref<Uint8Array[]>([]);
const fileInvalid = ref(0);
const busy = ref(false);
const fileInput = ref<HTMLInputElement | null>(null);
const MAX_FILE_SIZE = 1024 * 1024;

async function onFiles(e: Event) {
  const input = e.target as HTMLInputElement;
  const files = Array.from(input.files ?? []);
  fileDers.value = [];
  fileNames.value = [];
  fileInvalid.value = 0;
  for (const f of files) {
    if (f.size > MAX_FILE_SIZE) {
      fileInvalid.value++;
      continue;
    }
    const r = extractFromFile(new Uint8Array(await f.arrayBuffer()));
    fileDers.value.push(...r.ders);
    fileInvalid.value += r.invalidBlocks + (r.ders.length === 0 && r.invalidBlocks === 0 ? 1 : 0);
    fileNames.value.push(f.name);
  }
}

function clearAll() {
  text.value = "";
  fileDers.value = [];
  fileNames.value = [];
  fileInvalid.value = 0;
  card.value = null;
  if (fileInput.value) fileInput.value.value = "";
}

async function dedupe(ders: Uint8Array[]): Promise<Uint8Array[]> {
  const seen = new Set<string>();
  const out: Uint8Array[] = [];
  for (const d of ders) {
    const fp = await sha256Hex(d);
    if (!seen.has(fp)) {
      seen.add(fp);
      out.push(d);
    }
  }
  return out;
}

async function run() {
  busy.value = true;
  try {
    const fromText = extractPemCertificates(text.value);
    const ders = await dedupe([...fromText.ders, ...fileDers.value]);
    const invalid = fromText.invalidBlocks + fileInvalid.value;
    if (ders.length === 0) {
      card.value = {
        id: "paste",
        title: "貼上的憑證",
        status: "error",
        error: {
          code: "NO_CERTIFICATE",
          message: invalid
            ? "找到的憑證內容無法解碼，請確認 PEM 或 DER 格式是否完整"
            : "沒有找到憑證。請貼上包含 -----BEGIN CERTIFICATE----- 的內容，或上傳 .pem / .crt / .cer 檔案",
        },
      };
      return;
    }
    const result = await evaluate(ders, { mode: "paste" });
    if (invalid) {
      result.findings.unshift({
        level: "warning",
        code: "INPUT_SKIPPED",
        message: `有 ${invalid} 段內容無法解碼，已略過`,
      });
    }
    const leaf = result.chain.find((c) => c.role === "leaf");
    card.value = {
      id: "paste",
      title: leaf ? leaf.subject : "貼上的憑證",
      status: result.verdict,
      result,
    };
  } catch (e) {
    card.value = {
      id: "paste",
      title: "貼上的憑證",
      status: "error",
      error: { code: "PARSE_ERROR", message: `憑證格式錯誤，無法解析（${(e as Error).message}）` },
    };
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="panel" aria-label="貼上憑證">
    <p class="hint">
      完全在瀏覽器內檢查，不會上傳任何資料，離線也能使用。可貼上一或多段 PEM，例如
      <code class="mono">openssl s_client -connect 網站:443 -showcerts &lt;/dev/null</code> 的完整輸出。
    </p>
    <label class="field-label" for="pem-input">憑證內容（PEM）</label>
    <textarea
      id="pem-input"
      v-model="text"
      rows="8"
      spellcheck="false"
      autocomplete="off"
      class="mono"
      placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
    />
    <label class="file-label">
      <span>或上傳檔案（.pem、.crt、.cer，可多選；DER 與 PEM 皆可）</span>
      <input
        ref="fileInput"
        type="file"
        multiple
        accept=".pem,.crt,.cer,.der,application/x-x509-ca-cert,application/pkix-cert"
        @change="onFiles"
      />
    </label>
    <p v-if="fileNames.length" class="muted">已選擇 {{ fileNames.length }} 個檔案，找到 {{ fileDers.length }} 張憑證</p>
    <div class="actions">
      <button type="button" class="primary" :disabled="busy" @click="run">檢查</button>
      <button type="button" @click="clearAll">清除</button>
    </div>
    <div v-if="card" class="results">
      <ResultCard :card="card" />
    </div>
  </section>
</template>

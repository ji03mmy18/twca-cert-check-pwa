<script setup lang="ts">
import { computed, ref } from "vue";
import type { CardData } from "../types";

const props = defineProps<{ card: CardData }>();
const emit = defineEmits<{ switchToPaste: [] }>();

const LABELS: Record<CardData["status"], string> = {
  needs_update: "需要更新",
  ok: "看起來已更新完成",
  not_applicable: "不適用",
  error: "錯誤",
  pending: "檢查中…",
};
const LEVEL_LABELS = { affected: "受影響", warning: "警告", info: "資訊" } as const;

const label = computed(() =>
  props.card.waitSeconds ? `查詢次數已達上限，${props.card.waitSeconds} 秒後自動繼續…` : LABELS[props.card.status],
);
const showPasteHint = computed(() =>
  ["TLS13_ONLY", "TLS_ALERT", "CONNECT_FAILED", "NO_CERTIFICATE"].includes(props.card.error?.code ?? ""),
);
const copied = ref<string | null>(null);

function fmtDate(iso: string) {
  return iso.replace("T", " ").replace("Z", " UTC");
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    copied.value = text;
    setTimeout(() => (copied.value = null), 1500);
  } catch {
    window.prompt("請手動複製指紋：", text);
  }
}
</script>

<template>
  <article class="card" :class="`status-${card.status}`" aria-live="polite">
    <header class="card-head">
      <h3 class="card-title">{{ card.title }}</h3>
      <p class="verdict">{{ label }}</p>
    </header>

    <div v-if="card.error" class="error-body">
      <p>{{ card.error.message }}</p>
      <p class="muted mono">錯誤代碼：{{ card.error.code }}</p>
      <button v-if="showPasteHint" type="button" class="link-btn" @click="emit('switchToPaste')">
        改用「貼上憑證」模式 →
      </button>
    </div>

    <template v-if="card.result">
      <ul class="findings">
        <li v-for="(f, i) in card.result.findings" :key="i" :class="`level-${f.level}`">
          <span class="badge">{{ LEVEL_LABELS[f.level] }}</span>
          <span>{{ f.message }}</span>
        </li>
      </ul>

      <details class="chain">
        <summary>憑證鏈明細（{{ card.result.chain.length }} 張）</summary>
        <ol>
          <li v-for="(c, i) in card.result.chain" :key="i" class="cert" :class="{ affected: c.affected }">
            <p class="cert-role">
              {{ c.role === "leaf" ? "網站憑證" : "中繼憑證" }}
              <strong v-if="c.affected" class="affected-tag">在受影響清單中：{{ c.affected }}</strong>
            </p>
            <dl>
              <dt>主體</dt>
              <dd>{{ c.subject }}</dd>
              <dt>簽發者</dt>
              <dd>{{ c.issuer }}</dd>
              <dt>有效期間</dt>
              <dd>{{ fmtDate(c.notBefore) }} ～ {{ fmtDate(c.notAfter) }}</dd>
              <dt>SHA-256</dt>
              <dd class="fp">
                <code class="mono">{{ c.sha256 }}</code>
                <button type="button" class="copy-btn" @click="copy(c.sha256)">
                  {{ copied === c.sha256 ? "已複製" : "複製" }}
                </button>
              </dd>
            </dl>
          </li>
        </ol>
      </details>
    </template>
  </article>
</template>

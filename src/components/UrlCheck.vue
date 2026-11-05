<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import type { CheckResponse } from "../../shared/types";
import type { CardData } from "../types";
import ResultCard from "./ResultCard.vue";

const emit = defineEmits<{ switchToPaste: [] }>();

const MAX_TARGETS = 20;
const RATE_LIMIT_WAIT_SECONDS = 60;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const input = ref("");
const cards = ref<CardData[]>([]);
const running = ref(false);
const online = ref(typeof navigator === "undefined" ? true : navigator.onLine);
let cancelled = false;

const targets = computed(() => {
  const seen = new Set<string>();
  return input.value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !seen.has(s) && seen.add(s));
});
const tooMany = computed(() => targets.value.length > MAX_TARGETS);

function updateOnline() {
  online.value = navigator.onLine;
}
onMounted(() => {
  window.addEventListener("online", updateOnline);
  window.addEventListener("offline", updateOnline);
});
onBeforeUnmount(() => {
  window.removeEventListener("online", updateOnline);
  window.removeEventListener("offline", updateOnline);
});

async function checkOne(target: string): Promise<Omit<CardData, "id">> {
  let res: Response;
  try {
    res = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
      cache: "no-store",
    });
  } catch {
    return {
      title: target,
      status: "error",
      error: { code: "CONNECT_FAILED", message: "需要網路連線才能使用「輸入網址」模式。離線時請改用「貼上憑證」模式" },
    };
  }
  let body: CheckResponse;
  try {
    body = (await res.json()) as CheckResponse;
  } catch {
    return {
      title: target,
      status: "error",
      error: { code: "INTERNAL_ERROR", message: `伺服器回應格式錯誤（HTTP ${res.status}）` },
    };
  }
  if (!body.ok) return { title: target, status: "error", error: body.error };
  return { title: body.target, status: body.verdict, result: body };
}

async function run() {
  if (running.value || tooMany.value || targets.value.length === 0) return;
  running.value = true;
  cancelled = false;
  const list = targets.value;
  cards.value = list.map((t, i) => ({ id: `${Date.now()}-${i}`, title: t, status: "pending" }));
  try {
    // 依序查詢，不同時送出
    for (let i = 0; i < list.length; i++) {
      if (cancelled) break;
      let result = await checkOne(list[i]);
      // 超過速率限制（每分鐘 10 次）時，等待後自動重試一次
      if (result.error?.code === "RATE_LIMITED") {
        for (let s = RATE_LIMIT_WAIT_SECONDS; s > 0 && !cancelled; s--) {
          cards.value[i] = { ...cards.value[i], status: "pending", waitSeconds: s };
          await sleep(1000);
        }
        if (cancelled) break;
        cards.value[i] = { ...cards.value[i], waitSeconds: undefined };
        result = await checkOne(list[i]);
      }
      cards.value[i] = { ...cards.value[i], ...result };
    }
    if (cancelled) cards.value = cards.value.filter((c) => c.status !== "pending");
  } finally {
    running.value = false;
  }
}

function stop() {
  cancelled = true;
}
</script>

<template>
  <section class="panel" aria-label="輸入網址">
    <p v-if="!online" class="notice" role="status">
      需要網路連線才能使用「輸入網址」模式。離線時可以使用「<button
        type="button"
        class="link-btn"
        @click="emit('switchToPaste')"
      >
        貼上憑證</button
      >」模式。
    </p>
    <p class="hint">
      由伺服器連到網站，取得網站實際送出的憑證鏈並比對。一行一個，最多 {{ MAX_TARGETS }} 個，會依序查詢。
    </p>
    <label class="field-label" for="url-input">網址或網域</label>
    <textarea
      id="url-input"
      v-model="input"
      rows="4"
      spellcheck="false"
      autocapitalize="off"
      autocomplete="off"
      inputmode="url"
      placeholder="www.example.gov.tw&#10;https://example.com.tw:8443/"
      @keydown.enter.meta.prevent="run"
      @keydown.enter.ctrl.prevent="run"
    />
    <p v-if="tooMany" class="muted" role="alert">一次最多 {{ MAX_TARGETS }} 個，目前有 {{ targets.length }} 個</p>
    <div class="actions">
      <button
        type="button"
        class="primary"
        :disabled="running || !online || tooMany || targets.length === 0"
        @click="run"
      >
        {{ running ? "檢查中…" : "檢查" }}
      </button>
      <button v-if="running" type="button" @click="stop">停止</button>
    </div>
    <div v-if="cards.length" class="results">
      <ResultCard v-for="card in cards" :key="card.id" :card="card" @switch-to-paste="emit('switchToPaste')" />
    </div>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { AFFECTED_LIST_SOURCE, AFFECTED_LIST_UPDATED } from "../shared/affected";
import PasteCheck from "./components/PasteCheck.vue";
import UrlCheck from "./components/UrlCheck.vue";

type Tab = "url" | "paste";
const tab = ref<Tab>(location.hash === "#paste" ? "paste" : "url");

function select(t: Tab) {
  tab.value = t;
  history.replaceState(null, "", t === "paste" ? "#paste" : "#");
}

onMounted(() => {
  window.addEventListener("hashchange", () => {
    tab.value = location.hash === "#paste" ? "paste" : "url";
  });
});
</script>

<template>
  <div class="app">
    <header class="app-header">
      <img src="/icons/icon.svg" alt="" width="40" height="40" />
      <div>
        <h1>TWCA 憑證檢查</h1>
        <p class="subtitle">檢查網站是否仍使用受影響的 TWCA 中繼憑證（Bugzilla 2087236）</p>
      </div>
    </header>

    <main>
      <div class="tabs" role="tablist" aria-label="檢查模式">
        <button
          id="tab-url"
          role="tab"
          type="button"
          :aria-selected="tab === 'url'"
          aria-controls="panel-url"
          @click="select('url')"
        >
          輸入網址
        </button>
        <button
          id="tab-paste"
          role="tab"
          type="button"
          :aria-selected="tab === 'paste'"
          aria-controls="panel-paste"
          @click="select('paste')"
        >
          貼上憑證
        </button>
      </div>
      <div id="panel-url" role="tabpanel" aria-labelledby="tab-url" v-show="tab === 'url'">
        <UrlCheck @switch-to-paste="select('paste')" />
      </div>
      <div id="panel-paste" role="tabpanel" aria-labelledby="tab-paste" v-show="tab === 'paste'">
        <PasteCheck />
      </div>
    </main>

    <footer class="app-footer">
      <p>
        受影響清單更新日期：<time :datetime="AFFECTED_LIST_UPDATED">{{ AFFECTED_LIST_UPDATED }}</time> ・<a
          :href="AFFECTED_LIST_SOURCE"
          target="_blank"
          rel="noopener noreferrer"
          >Bugzilla 2087236</a
        >
      </p>
      <p>本工具僅比對已公開的受影響憑證清單，結果不代表 TWCA 官方認定。</p>
    </footer>
  </div>
</template>

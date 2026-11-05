#!/usr/bin/env bash
# 本機整合測試：啟動只開 TLS 1.2 / 只開 TLS 1.3 的 openssl 測試伺服器，呼叫開發伺服器的 /api/check。
#
# 前置作業：
#   1. .env 內設定 DEV_ALLOW_PRIVATE_TARGETS=true（只在開發伺服器生效）
#   2. 另一個終端機執行 npm run dev
# 用法：bash scripts/integration-test.sh [http://localhost:5173]
set -euo pipefail
BASE="${1:-http://localhost:5173}"
FIX="$(cd "$(dirname "$0")/../test/fixtures" && pwd)"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

openssl s_server -accept 14433 -cert "$FIX/leaf-old.crt" -key "$FIX/leaf.key" -cert_chain "$FIX/ca.crt" -tls1_2 -quiet >/dev/null 2>&1 &
pids+=($!)
openssl s_server -accept 14434 -cert "$FIX/leaf-old.crt" -key "$FIX/leaf.key" -cert_chain "$FIX/ca.crt" -tls1_3 -quiet >/dev/null 2>&1 &
pids+=($!)
openssl s_server -accept 14435 -cert "$FIX/leaf-new.crt" -key "$FIX/leaf.key" -cert_chain "$FIX/ca.crt" -tls1_2 -quiet >/dev/null 2>&1 &
pids+=($!)
sleep 1

fail=0
check() {
  local target="$1" expect="$2"
  local body
  body=$(curl -s -X POST "$BASE/api/check" -H 'Content-Type: application/json' -d "{\"target\":\"$target\"}")
  if grep -q "$expect" <<<"$body"; then
    echo "PASS  $target → $expect"
  else
    echo "FAIL  $target → expected $expect, got: ${body:0:300}"
    fail=1
  fi
}

check "localhost:14433" '"verdict":"needs_update"'
check "localhost:14433" '"code":"LEAF_BEFORE_REISSUE"'
check "localhost:14433" '"role":"intermediate"'
check "localhost:14434" '"code":"TLS13_ONLY"'
check "localhost:14435" '"verdict":"ok"'
check "localhost:1" '"code":"CONNECT_FAILED"'

exit $fail

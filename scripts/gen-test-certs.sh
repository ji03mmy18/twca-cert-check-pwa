#!/usr/bin/env bash
# 產生測試用憑證（僅供單元 / 整合測試，與真實 TWCA 無關）。
# 需要 OpenSSL 3.4 以上（使用 -not_before / -not_after）。
set -euo pipefail
cd "$(dirname "$0")/../test/fixtures"

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

# 假的 TWCA 根憑證與中繼憑證（名稱模仿 TWCA，僅用於測試 issuer 判斷）
key root.key
openssl req -x509 -new -key root.key -subj "/C=TW/O=TAIWAN-CA/CN=Test TWCA Root" \
  -not_before 20200101000000Z -not_after 20551231235959Z \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out root.crt

key ca.key
openssl req -new -key ca.key -subj "/C=TW/O=TAIWAN-CA/OU=Test/CN=Test TWCA SSL Certification Authority" -out ca.csr
openssl x509 -req -in ca.csr -CA root.crt -CAkey root.key -set_serial 2 \
  -not_before 20230101000000Z -not_after 20330101000000Z \
  -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n") \
  -out ca.crt 2>/dev/null

# 網站憑證：舊版（2025 簽發）與新版（2026-11-01 簽發），使用同一把金鑰
key leaf.key
openssl req -new -key leaf.key -subj "/CN=localhost" -out leaf.csr
leafext=$(printf "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -set_serial 100 \
  -not_before 20250520000000Z -not_after 20270620235959Z -extfile <(echo "$leafext") -out leaf-old.crt 2>/dev/null
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -set_serial 101 \
  -not_before 20261101000000Z -not_after 20271201235959Z -extfile <(echo "$leafext") -out leaf-new.crt 2>/dev/null
# 沒有 basicConstraints 的網站憑證
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -set_serial 102 \
  -not_before 20261101000000Z -not_after 20271201235959Z \
  -extfile <(printf "subjectAltName=DNS:localhost\n") -out leaf-nobc.crt 2>/dev/null

# 非 TWCA 的憑證鏈
key other-ca.key
openssl req -x509 -new -key other-ca.key -subj "/C=US/O=Example Trust/CN=Example Issuing CA" \
  -not_before 20240101000000Z -not_after 20340101000000Z \
  -addext "basicConstraints=critical,CA:TRUE" -out other-ca.crt
openssl x509 -req -in leaf.csr -CA other-ca.crt -CAkey other-ca.key -set_serial 7 \
  -not_before 20250101000000Z -not_after 20260101000000Z -extfile <(echo "$leafext") -out other-leaf.crt 2>/dev/null

openssl x509 -in leaf-old.crt -outform DER -out leaf-old.der
rm -f *.csr *.srl
echo "fixtures generated"

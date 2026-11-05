import { describe, expect, it } from "vite-plus/test";
import { extractFromFile, extractPemCertificates } from "../shared/pem";
import { fixtureDer, fixtureText } from "./helpers";
import { readFileSync } from "node:fs";
import { fixturePath } from "./helpers";

describe("PEM extraction", () => {
  it("extracts multiple PEM blocks and ignores surrounding text", () => {
    const text = `CONNECTED(00000003)
depth=1 C=TW, O=TAIWAN-CA, CN=Test
---
Certificate chain
 0 s:CN=localhost
   i:C=TW, O=TAIWAN-CA, OU=Test, CN=Test TWCA SSL Certification Authority
${fixtureText("leaf-old.crt")}
 1 s:C=TW, O=TAIWAN-CA, OU=Test, CN=Test TWCA SSL Certification Authority
${fixtureText("ca.crt")}---
Server certificate
subject=CN=localhost
SSL handshake has read 1234 bytes`;
    const { ders, invalidBlocks } = extractPemCertificates(text);
    expect(ders).toHaveLength(2);
    expect(invalidBlocks).toBe(0);
    expect(ders[0]).toEqual(fixtureDer("leaf-old.crt"));
    expect(ders[1]).toEqual(fixtureDer("ca.crt"));
  });

  it("handles CRLF line endings and indentation", () => {
    const pem = fixtureText("ca.crt").replace(/\n/g, "\r\n    ");
    expect(extractPemCertificates(pem).ders[0]).toEqual(fixtureDer("ca.crt"));
  });

  it("counts broken blocks", () => {
    const r = extractPemCertificates("-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----");
    expect(r.ders).toHaveLength(0);
    expect(r.invalidBlocks).toBe(1);
  });

  it("returns nothing for plain text", () => {
    expect(extractPemCertificates("hello world").ders).toHaveLength(0);
  });
});

describe("file extraction", () => {
  it("accepts DER files", () => {
    const bytes = new Uint8Array(readFileSync(fixturePath("leaf-old.der")));
    expect(extractFromFile(bytes).ders).toEqual([bytes]);
  });

  it("accepts PEM files with multiple certs", () => {
    const bytes = new TextEncoder().encode(fixtureText("leaf-old.crt") + fixtureText("ca.crt"));
    expect(extractFromFile(bytes).ders).toHaveLength(2);
  });
});

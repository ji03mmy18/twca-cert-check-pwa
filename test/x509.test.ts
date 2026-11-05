import { describe, expect, it } from "vite-plus/test";
import { decodeTime, DerError, readTlv } from "../shared/der";
import { parseCertificate, parseCertificateFields } from "../shared/x509";
import { fixtureDer } from "./helpers";

describe("parseCertificate", () => {
  it("parses subject, issuer, validity, CA flag and fingerprint", async () => {
    const c = await parseCertificate(fixtureDer("leaf-old.crt"));
    expect(c.subject).toBe("CN=localhost");
    expect(c.issuer).toBe("C=TW, O=TAIWAN-CA, OU=Test, CN=Test TWCA SSL Certification Authority");
    expect(c.notBefore.toISOString()).toBe("2025-05-20T00:00:00.000Z");
    expect(c.notAfter.toISOString()).toBe("2027-06-20T23:59:59.000Z");
    expect(c.isCA).toBe(false);
    expect(c.sha256).toBe("ad3ab8a3eb548b3cde3f21ef8d1681d6addad4fc0f51f74efa87f850bdb60032");
  });

  it("detects CA certificates and missing basicConstraints", async () => {
    expect((await parseCertificate(fixtureDer("ca.crt"))).isCA).toBe(true);
    expect((await parseCertificate(fixtureDer("leaf-nobc.crt"))).isCA).toBe(null);
  });

  it("handles GeneralizedTime (dates after 2049)", async () => {
    const root = await parseCertificate(fixtureDer("root.crt"));
    expect(root.notAfter.toISOString()).toBe("2055-12-31T23:59:59.000Z");
  });

  it("reads binary DER identical to PEM", async () => {
    const a = await parseCertificate(fixtureDer("leaf-old.der"));
    const b = await parseCertificate(fixtureDer("leaf-old.crt"));
    expect(a.sha256).toBe(b.sha256);
  });

  it("throws DerError on every truncation, never anything else", () => {
    const der = fixtureDer("leaf-old.crt");
    for (let n = 0; n < der.length; n++) {
      expect(() => parseCertificateFields(der.subarray(0, n))).toThrow(DerError);
    }
  });

  it("throws DerError on random corruption", () => {
    const der = fixtureDer("ca.crt");
    let seed = 42;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    for (let i = 0; i < 2000; i++) {
      const copy = der.slice();
      for (let k = 0; k < 3; k++) copy[Math.floor(rnd() * copy.length)] = Math.floor(rnd() * 256);
      try {
        parseCertificateFields(copy);
      } catch (e) {
        expect(e).toBeInstanceOf(DerError);
      }
    }
  });
});

describe("der", () => {
  it("rejects lengths that exceed the buffer", () => {
    expect(() => readTlv(new Uint8Array([0x30, 0x82, 0xff, 0xff, 0x00]), 0)).toThrow(DerError);
    expect(() => readTlv(new Uint8Array([0x30, 0x85, 1, 1, 1, 1, 1]), 0)).toThrow(DerError);
  });

  it("decodes UTCTime century rule", () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(decodeTime(0x17, enc("491231235959Z")).getUTCFullYear()).toBe(2049);
    expect(decodeTime(0x17, enc("500101000000Z")).getUTCFullYear()).toBe(1950);
    expect(decodeTime(0x18, enc("20501231235959Z")).getUTCFullYear()).toBe(2050);
    expect(() => decodeTime(0x17, enc("2501010000Z"))).toThrow(DerError);
  });
});

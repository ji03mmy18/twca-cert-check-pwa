import { afterEach, describe, expect, it } from "vite-plus/test";
import { AFFECTED_INTERMEDIATES } from "../shared/affected";
import { evaluate } from "../shared/evaluate";
import { sha256Hex } from "../shared/x509";
import { fixtureDer } from "./helpers";

const leafOld = fixtureDer("leaf-old.crt");
const leafNew = fixtureDer("leaf-new.crt");
const leafNoBc = fixtureDer("leaf-nobc.crt");
const ca = fixtureDer("ca.crt");
const root = fixtureDer("root.crt");
const otherLeaf = fixtureDer("other-leaf.crt");
const otherCa = fixtureDer("other-ca.crt");

const codes = (r: { findings: { code: string }[] }) => r.findings.map((f) => f.code);

async function markAffected(der: Uint8Array) {
  const fp = await sha256Hex(der);
  AFFECTED_INTERMEDIATES[fp] = "Test TWCA SSL Certification Authority (test)";
  return fp;
}
const added: string[] = [];
afterEach(() => {
  for (const fp of added.splice(0)) delete AFFECTED_INTERMEDIATES[fp];
});

describe("evaluate (server mode)", () => {
  it("not_applicable when issuer is not TWCA", async () => {
    const r = await evaluate([otherLeaf, otherCa]);
    expect(r.verdict).toBe("not_applicable");
    expect(codes(r)).toEqual(["NOT_TWCA"]);
  });

  it("needs_update when intermediate fingerprint is on the list", async () => {
    added.push(await markAffected(ca));
    const r = await evaluate([leafNew, ca]);
    expect(r.verdict).toBe("needs_update");
    expect(codes(r)).toEqual(["AFFECTED_INTERMEDIATE"]);
    expect(r.chain[1].affected).toBe("Test TWCA SSL Certification Authority (test)");
    expect(r.chain[0].role).toBe("leaf");
    expect(r.chain[1].role).toBe("intermediate");
  });

  it("needs_update when leaf was issued before reissue date", async () => {
    const r = await evaluate([leafOld, ca]);
    expect(r.verdict).toBe("needs_update");
    expect(codes(r)).toEqual(["LEAF_BEFORE_REISSUE"]);
  });

  it("reports both findings together", async () => {
    added.push(await markAffected(ca));
    const r = await evaluate([leafOld, ca]);
    expect(codes(r)).toEqual(["AFFECTED_INTERMEDIATE", "LEAF_BEFORE_REISSUE"]);
  });

  it("ok when new leaf and unaffected intermediate", async () => {
    const r = await evaluate([leafNew, ca]);
    expect(r.verdict).toBe("ok");
    expect(codes(r)).toEqual(["LOOKS_UPDATED"]);
    expect(r.listUpdated).toBe("2026-11-05");
    expect(r.chain[0].notBefore).toBe("2026-11-01T00:00:00Z");
  });

  it("warns on incomplete chain", async () => {
    const r = await evaluate([leafNew]);
    expect(r.verdict).toBe("ok");
    expect(codes(r)).toContain("CHAIN_INCOMPLETE");
  });

  it("server mode does not reorder", async () => {
    const r = await evaluate([ca, leafNew]);
    expect(r.chain[0].subject).toContain("Test TWCA SSL Certification Authority");
  });

  it("rejects garbage input", async () => {
    await expect(evaluate([new Uint8Array([1, 2, 3])])).rejects.toThrow();
  });
});

describe("evaluate (paste mode)", () => {
  it("finds the leaf by basicConstraints when order is wrong", async () => {
    const r = await evaluate([root, ca, leafOld], { mode: "paste" });
    expect(r.chain[0].subject).toBe("CN=localhost");
    expect(r.chain.map((c) => c.role)).toEqual(["leaf", "intermediate", "intermediate"]);
    expect(codes(r)).toContain("ORDER_ADJUSTED");
    expect(codes(r)).toContain("LEAF_BEFORE_REISSUE");
  });

  it("treats a cert without basicConstraints as leaf", async () => {
    const r = await evaluate([ca, leafNoBc], { mode: "paste" });
    expect(r.chain[0].subject).toBe("CN=localhost");
    expect(r.verdict).toBe("ok");
  });

  it("only leaf pasted", async () => {
    const r = await evaluate([leafNew], { mode: "paste" });
    expect(codes(r)).toContain("CHAIN_INCOMPLETE");
    expect(r.verdict).toBe("ok");
  });

  it("only intermediates pasted", async () => {
    added.push(await markAffected(ca));
    const r = await evaluate([ca, root], { mode: "paste" });
    expect(codes(r)).toEqual(["NO_LEAF", "AFFECTED_INTERMEDIATE"]);
    expect(r.verdict).toBe("needs_update");
  });

  it("falls back to paste order when ambiguous", async () => {
    const r = await evaluate([leafNew, leafOld, ca], { mode: "paste" });
    expect(codes(r)[0]).toBe("ORDER_UNCERTAIN");
    expect(r.chain[0].notBefore).toBe("2026-11-01T00:00:00Z");
  });
});

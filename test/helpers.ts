import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { extractPemCertificates } from "../shared/pem";

export function fixturePath(name: string): string {
  return fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
}

export function fixtureText(name: string): string {
  return readFileSync(fixturePath(name), "utf8");
}

export function fixtureDer(name: string): Uint8Array {
  if (name.endsWith(".der")) return new Uint8Array(readFileSync(fixturePath(name)));
  const { ders } = extractPemCertificates(fixtureText(name));
  if (ders.length !== 1) throw new Error(`expected 1 cert in ${name}`);
  return ders[0];
}

import { describe, expect, it } from "vite-plus/test";
import { isBlockedIPv6, parseIPv6, parseTarget } from "../server/target";

const code = (input: unknown, allowPrivate = false) => {
  const r = parseTarget(input, { allowPrivate });
  return r.ok ? "OK" : r.error.code;
};

describe("parseTarget: accepted inputs", () => {
  it.each([
    ["example.com", "example.com", 443, "example.com"],
    ["  Example.COM  ", "example.com", 443, "example.com"],
    ["example.com:8443", "example.com", 8443, "example.com"],
    ["https://www.example.gov.tw/path?q=1#x", "www.example.gov.tw", 443, "www.example.gov.tw"],
    ["https://example.com:443/", "example.com", 443, "example.com"],
    ["http://example.com", "example.com", 443, "example.com"],
    ["example.com.", "example.com", 443, "example.com"],
    ["8.8.8.8", "8.8.8.8", 443, null],
    ["[2606:4700:4700::1111]:8443", "2606:4700:4700::1111", 8443, null],
    ["例え.jp", "xn--r8jz45g.jp", 443, "xn--r8jz45g.jp"],
  ])("%s", (input, host, port, sni) => {
    const r = parseTarget(input);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.target.host).toBe(host);
      expect(r.target.port).toBe(port);
      expect(r.target.serverName).toBe(sni);
    }
  });

  it("formats display target", () => {
    const r = parseTarget("[2001:4860:4860::8888]");
    expect(r.ok && r.target.display).toBe("[2001:4860:4860::8888]:443");
  });
});

describe("parseTarget: rejected inputs", () => {
  it.each([
    ["", "INVALID_TARGET"],
    [42, "INVALID_TARGET"],
    [null, "INVALID_TARGET"],
    ["exa mple.com", "INVALID_TARGET"],
    ["ftp://example.com", "INVALID_TARGET"],
    ["user:pw@example.com", "INVALID_TARGET"],
    ["example", "INVALID_TARGET"],
    ["-bad-.com", "INVALID_TARGET"],
    ["a_b.example.com", "INVALID_TARGET"],
    [`${"a".repeat(64)}.com`, "INVALID_TARGET"],
    ["example.com:99999", "INVALID_TARGET"],
    ["x".repeat(3000), "INVALID_TARGET"],
    ["[::g]", "INVALID_TARGET"],
    ["example.com:80", "PORT_NOT_ALLOWED"],
    ["example.com:22", "PORT_NOT_ALLOWED"],
    ["http://example.com:80", "PORT_NOT_ALLOWED"],
    ["8.8.8.8:25", "PORT_NOT_ALLOWED"],
  ])("%s → %s", (input, expected) => {
    expect(code(input)).toBe(expected);
  });
});

describe("parseTarget: blocked addresses", () => {
  it.each([
    "localhost",
    "LOCALHOST:443",
    "foo.localhost",
    "printer.local",
    "db.internal",
    "router.home.arpa",
    "0.0.0.0",
    "10.1.2.3",
    "100.64.0.1",
    "100.127.255.255",
    "127.0.0.1",
    "127.1",
    "0x7f.1",
    "2130706433",
    "169.254.169.254",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "192.0.2.10",
    "198.18.0.1",
    "224.0.0.1",
    "255.255.255.255",
    "[::]",
    "[::1]",
    "[::ffff:127.0.0.1]",
    "[::ffff:7f00:1]",
    "[64:ff9b::a00:1]",
    "[fc00::1]",
    "[fd12:3456::1]",
    "[fe80::1]",
    "[ff02::1]",
    "[2001:db8::1]",
    "[2002:c0a8:101::1]",
    "https://[::1]:8443/",
  ])("%s", (input) => {
    expect(code(input)).toBe("BLOCKED_ADDRESS");
  });

  it("allows public neighbours of private ranges", () => {
    for (const ip of ["9.255.255.255", "11.0.0.1", "100.128.0.1", "172.15.255.255", "172.32.0.1", "192.169.0.1"]) {
      expect(code(ip)).toBe("OK");
    }
  });

  it("dev mode relaxes restrictions", () => {
    expect(code("localhost:14433", true)).toBe("OK");
    expect(code("127.0.0.1:14434", true)).toBe("OK");
    expect(code("[::1]:14433", true)).toBe("OK");
  });
});

describe("IPv6 parsing", () => {
  it("expands addresses", () => {
    expect(parseIPv6("::1")).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(parseIPv6("2001:db8::")).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]);
    expect(parseIPv6("::ffff:1.2.3.4")).toEqual([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]);
    expect(parseIPv6("1:2:3:4:5:6:7:8")).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });
  it("rejects malformed addresses", () => {
    for (const s of ["1::2::3", "1:2:3:4:5:6:7:8:9", "12345::", "1:2:3", ":::", "fe80::1%eth0"]) {
      expect(parseIPv6(s)).toBeNull();
    }
  });
  it("only allows global unicast", () => {
    expect(isBlockedIPv6(parseIPv6("2606:4700::1")!)).toBe(false);
    expect(isBlockedIPv6(parseIPv6("4000::1")!)).toBe(true);
  });
});

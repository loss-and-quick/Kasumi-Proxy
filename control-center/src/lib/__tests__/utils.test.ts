import { describe, expect, it } from "vitest";
import { isInsecureHttpUrl, isLocalOrPrivateHost } from "../utils";

describe("isLocalOrPrivateHost", () => {
  it("treats localhost and *.local as private", () => {
    expect(isLocalOrPrivateHost("http://localhost:8080/sub")).toBe(true);
    expect(isLocalOrPrivateHost("https://router.local/sub")).toBe(true);
    expect(isLocalOrPrivateHost("http://box.localhost/sub")).toBe(true);
  });

  it("treats private and loopback IPv4 ranges as private", () => {
    expect(isLocalOrPrivateHost("http://127.0.0.1/sub")).toBe(true);
    expect(isLocalOrPrivateHost("http://10.1.2.3/sub")).toBe(true);
    expect(isLocalOrPrivateHost("http://192.168.0.5/sub")).toBe(true);
    expect(isLocalOrPrivateHost("http://172.16.0.1/sub")).toBe(true);
    expect(isLocalOrPrivateHost("http://172.31.255.255/sub")).toBe(true);
    expect(isLocalOrPrivateHost("http://169.254.1.1/sub")).toBe(true);
  });

  it("treats IPv6 loopback / ULA / link-local as private", () => {
    expect(isLocalOrPrivateHost("http://[::1]:9000/sub")).toBe(true);
    expect(isLocalOrPrivateHost("http://[fd00::1]/sub")).toBe(true);
    expect(isLocalOrPrivateHost("http://[fe80::1]/sub")).toBe(true);
  });

  it("treats public hosts as not private", () => {
    expect(isLocalOrPrivateHost("https://example.com/sub")).toBe(false);
    expect(isLocalOrPrivateHost("http://8.8.8.8/sub")).toBe(false);
    expect(isLocalOrPrivateHost("https://172.32.0.1/sub")).toBe(false); // just outside 172.16/12
    expect(isLocalOrPrivateHost("https://fcuk.example.com/sub")).toBe(false); // domain, not fc00::/7
  });

  it("returns false for malformed input", () => {
    expect(isLocalOrPrivateHost("not a url")).toBe(false);
    expect(isLocalOrPrivateHost("")).toBe(false);
  });
});

describe("isInsecureHttpUrl", () => {
  it("flags plain http only", () => {
    expect(isInsecureHttpUrl("http://example.com")).toBe(true);
    expect(isInsecureHttpUrl("https://example.com")).toBe(false);
    expect(isInsecureHttpUrl("garbage")).toBe(false);
  });
});

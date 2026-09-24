import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { Profile, Tls } from "../../../generated/bindings";
import { CredentialsSection } from "./CredentialsSection";
import { SecuritySection } from "./SecuritySection";

const noop = () => {};

const securityMarkup = (tls: Tls) =>
  renderToStaticMarkup(
    createElement(SecuritySection, {
      tls,
      setTls: noop,
      errors: {},
      isTls: true,
      isReality: false,
      isQuic: false,
    }),
  );

const wireguard = (reserved: number[]): Profile => ({
  protocol: "wireguard",
  meta: { id: "w", remarks: "r", groupId: "g-main" },
  endpoint: { address: "e.x", port: 51820 },
  secretKey: "sk",
  peerPublicKey: "pk",
  reserved,
});

// A single-line <input> applies the HTML value sanitization algorithm ("strip
// newlines"), so a newline-joined list would render as one glued-together token
// and collapse into a single bogus entry on the next edit. Every field fed by
// `toText` must therefore be a textarea.
describe("list settings render in an input that can hold their separator", () => {
  it("puts the newline-joined TLS lists in textareas", () => {
    const html = securityMarkup({
      alpn: ["h2", "http/1.1"],
      tlsCipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
      tlsCurvePreferences: ["X25519", "P-256"],
    });
    for (const joined of [
      "h2\nhttp/1.1",
      "TLS_AES_128_GCM_SHA256\nTLS_AES_256_GCM_SHA384",
      "X25519\nP-256",
    ]) {
      expect(html).toContain(`>${joined}</textarea>`);
    }
  });

  it("keeps the reserved byte triple comma-joined on one line", () => {
    const html = renderToStaticMarkup(
      createElement(CredentialsSection, {
        draft: wireguard([1, 2, 3]),
        setRoot: noop,
        errors: {},
      }),
    );
    expect(html).toContain('value="1, 2, 3"');
    expect(html).not.toContain("1\n2\n3");
  });
});

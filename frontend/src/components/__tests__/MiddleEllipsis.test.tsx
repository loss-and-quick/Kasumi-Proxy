import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { MiddleEllipsis } from "../display";

describe("MiddleEllipsis", () => {
  it("keeps the last characters in a part of their own and the whole text as the title", () => {
    const html = renderToStaticMarkup(<MiddleEllipsis text="edge.example.net:8443" tail={8} />);
    expect(html).toContain('title="edge.example.net:8443"');
    expect(html).toContain('<span class="mid-head">edge.example.</span>');
    expect(html).toContain('<span class="mid-tail">net:8443</span>');
  });

  it("splits by code point, so a surrogate pair stays whole", () => {
    const html = renderToStaticMarkup(<MiddleEllipsis text="a😀b😀" tail={2} />);
    expect(html).toContain('<span class="mid-head">a😀</span>');
    expect(html).toContain('<span class="mid-tail">b😀</span>');
  });

  it("is all tail when the text is shorter than it", () => {
    const html = renderToStaticMarkup(<MiddleEllipsis text="ab" tail={5} />);
    expect(html).toContain('<span class="mid-head"></span><span class="mid-tail">ab</span>');
  });
});

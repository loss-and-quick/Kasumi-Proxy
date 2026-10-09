import { describe, expect, it } from "vitest";
import { assetDraftErrors } from "../helpers";

const t = (key: string) => key;
const errors = (remarks: string, url: string, taken: string[] = []) =>
  assetDraftErrors({ remarks, url }, taken, t);

describe("assetDraftErrors", () => {
  it("accepts a plain file name and an http(s) link", () => {
    expect(errors("geoip.dat", "https://example.com/geoip.dat")).toEqual({});
    expect(errors(" geosite.dat ", "http://example.com/g")).toEqual({});
  });

  it("asks for a name and a link", () => {
    expect(errors("", "")).toEqual({
      remarks: "assetSheet.validation.filename",
      url: "assetSheet.validation.url",
    });
  });

  it("refuses names the backend won't download into", () => {
    for (const name of ["../x.dat", "a/b.dat", "a\\b.dat", 'a"b.dat', "x..dat"]) {
      expect(errors(name, "https://e.com").remarks).toBe("assetSheet.validation.filenameUnsafe");
    }
  });

  it("refuses a name another entry already uses", () => {
    expect(errors("geoip.dat", "https://e.com", ["geoip.dat"]).remarks).toBe(
      "assetSheet.validation.filenameTaken",
    );
  });

  it("refuses links that aren't http(s)", () => {
    expect(errors("a.dat", "ftp://e.com/a").url).toBe("assetSheet.validation.url");
    expect(errors("a.dat", "example.com/a").url).toBe("assetSheet.validation.url");
  });
});

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { Profile, Protocol } from "../../../generated/bindings";
import { type PickerChoice, ProfilePickerList, pickerSections } from "../ProfilePicker";

const p = (id: string, remarks: string, groupId: string, protocol: Protocol, host: string) =>
  ({
    protocol,
    meta: { id, remarks, groupId },
    endpoint: { address: host, port: 443 },
  }) as unknown as Profile;

const groups = [
  { id: "g1", name: "Gosha 1" },
  { id: "g2", name: "Gosha 2" },
];
const profiles = [
  p("a", "Finland", "g1", "vless", "fi1.example"),
  p("b", "Sweden", "g1", "trojan", "se.example"),
  p("c", "Finland", "g2", "hysteria2", "fi2.example"),
  p("d", "Finland", "g2", "vless", "fi3.example"),
];

/** Renders the list and reads back its section headers and option rows (no DOM in node tests). */
function render(query: string, value: string, choices: PickerChoice[] = []) {
  const html = renderToStaticMarkup(
    <ProfilePickerList
      sections={pickerSections(profiles, groups, query)}
      choices={choices}
      value={value}
      tests={{ c: { ping: 87 } }}
      onPick={() => {}}
    />,
  );
  const sections = [...html.matchAll(/class="section-label"><span>([^<]*)</g)].map((m) => m[1]);
  const rows = [
    ...html.matchAll(/role="option" aria-selected="(true|false)"[\s\S]*?<\/button>/g),
  ].map((m) => ({
    selected: m[1] === "true",
    name: /picker-row-name[^>]*>([^<]*)</.exec(m[0])?.[1],
    endpoint: /dir="ltr"[^>]*>([^<]*)</.exec(m[0])?.[1],
    text: m[0],
  }));
  return { html, sections, rows };
}

describe("ProfilePickerList", () => {
  it("lists every profile under its group, with protocol and host:port", () => {
    const view = render("", "");
    expect(view.sections).toEqual(["Gosha 1", "Gosha 2"]);
    expect(view.rows.map((r) => `${r.name} ${r.endpoint}`)).toEqual([
      "Finland fi1.example:443",
      "Sweden se.example:443",
      "Finland fi2.example:443",
      "Finland fi3.example:443",
    ]);
    expect(view.rows[2].text).toContain("hysteria2");
    expect(view.rows[2].text).toContain("87");
  });

  it("filters by name, protocol or address and drops groups left empty", () => {
    expect(render("sweden", "").sections).toEqual(["Gosha 1"]);
    const hy2 = render("hysteria2", "");
    expect(hy2.sections).toEqual(["Gosha 2"]);
    expect(hy2.rows.map((r) => r.endpoint)).toEqual(["fi2.example:443"]);
    expect(render("fi3.example", "").rows.map((r) => r.endpoint)).toEqual(["fi3.example:443"]);
    expect(render("nothing-like-this", "").html).toContain("common.noMatches");
  });

  it("marks the current pick, profile or built-in choice", () => {
    const rows = render("", "d").rows;
    expect(rows.filter((r) => r.selected).map((r) => r.endpoint)).toEqual(["fi3.example:443"]);
    const choices = [{ value: "proxy", label: "Proxy", icon: "shield_moon" }];
    const withChoice = render("", "proxy", choices).rows;
    expect(withChoice[0]).toMatchObject({ selected: true, name: "Proxy" });
    expect(withChoice.filter((r) => r.selected)).toHaveLength(1);
  });

  it("keeps a blocked profile listed, disabled and with its reason", () => {
    const html = renderToStaticMarkup(
      <ProfilePickerList
        sections={pickerSections(profiles, groups, "")}
        choices={[]}
        value="a"
        tests={{}}
        blocked={
          new Map([
            ["b", "needs sing-box"],
            ["a", "ignored while picked"],
          ])
        }
        onPick={() => {}}
      />,
    );
    expect(html.match(/<button[^>]*disabled=""/g)).toHaveLength(1);
    expect(html).toContain("needs sing-box");
    expect(html).not.toContain("ignored while picked");
  });
});

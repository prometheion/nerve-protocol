// The web UIs look like the app: every token of tokens.css is the value of
// the same name in the app's theme.slint, light and dark; a column folds
// where its panes no longer fit.
import { describe, expect, it } from "vitest";
import theme from "../../crates/nerve/ui/theme.slint?raw";
import tokens from "./styles/tokens.css?raw";
import app from "./styles/app.css?raw";

/** `name: value` of each declaration in the first block after `head`. */
function block(css: string, head: string): Map<string, string> {
  const at = css.indexOf(head);
  if (at < 0) throw new Error(`no ${head}`);
  const body = css.slice(css.indexOf("{", at) + 1, css.indexOf("}", at));
  return new Map(
    Array.from(body.matchAll(/--([\w-]+):\s*([^;]+);/g), (m) => [m[1], m[2].trim()] as [string, string]),
  );
}

function global(name: string): [string, string][] {
  const at = theme.indexOf(`export global ${name} {`);
  const body = theme.slice(at, theme.indexOf("\n}", at));
  return Array.from(body.matchAll(/out property <\w+> ([\w-]+): ([^;]+);/g), (m) => [m[1], m[2]]);
}

const light = block(tokens, ":root {");
const dark = block(tokens, ':root[data-theme="dark"] {');
const darkSystem = block(tokens, ":root:not([data-theme]) {");

describe("the design tokens", () => {
  it("are the app's colours, light and dark", () => {
    const colours = global("Theme").filter(([, v]) => v.startsWith("dark ?"));
    expect(colours.length).toBeGreaterThanOrEqual(30);
    for (const [name, v] of colours) {
      const [, d, l] = v.match(/dark \? (#\w+) : (#\w+)/)!;
      expect(light.get(name), `light ${name}`).toBe(l);
      expect(dark.get(name), `dark ${name}`).toBe(d);
      expect(darkSystem.get(name), `system dark ${name}`).toBe(d);
    }
  });

  it("are the app's type, spaces, radii and sizes", () => {
    const sets: [string, string][] = [
      ["Space", "space"],
      ["Radius", "radius"],
      ["Size", "size"],
    ];
    for (const [g, prefix] of sets) {
      for (const [name, v] of global(g)) expect(light.get(`${prefix}-${name}`), `${g}.${name}`).toBe(v);
    }
    for (const [name, v] of global("Type").filter(([n]) => n !== "mono")) {
      const key = /^\d+$/.test(v) ? `weight-${name}` : `type-${name}`;
      expect(light.get(key), `Type.${name}`).toBe(v);
    }
  });

  it("move as the app does", () => {
    const motion = global("Motion");
    for (const name of ["quick", "base", "enter", "leave", "rise"]) {
      const v = motion.find(([n]) => n === name)![1];
      const on = v.match(/on \? (\w+) : /)![1];
      expect(light.get(`motion-${name}`), `Motion.${name}`).toBe(on);
    }
  });

  // A column folds only where the panes no longer fit at their least
  // widths, by the page's own width, not at fixed window widths (owner,
  // #213): two panes at 260 + 400 px and the gap, three at 260 + 440 + 300.
  it("fold a column only where the panes no longer fit", () => {
    expect(app).not.toMatch(/@media \(min-width: 1800px\)/);
    const gap = Number(tokens.match(/--space-lg: (\d+)px/)![1]);
    const two = Number(app.match(/@container page \(min-width: (\d+)px\) \{\n  \.split \{/)![1]);
    expect(two).toBeGreaterThanOrEqual(260 + gap + 400);
    expect(app).toContain(`@container page (max-width: ${two - 1}px)`);
    const three = Number(app.match(/@container page \(min-width: (\d+)px\) \{\n  \.split\.side3 \{/)![1]);
    expect(three).toBeGreaterThanOrEqual(260 + 440 + 300 + 2 * gap);
    expect(app).toContain("minmax(260px, var(--lw)) minmax(400px, var(--dw))");
  });

  // A width the owner dragged to (data-w) wins at every page width: each
  // rule that sets a Split's columns without minding data-w is followed, in
  // its own block, by a data-w rule of the same Split at least as weighty
  // (owner, #213: the shares hold as the window changes).
  it("let a dragged width win on every page width", () => {
    const blocks = Array.from(app.matchAll(/@container page \(min-width: \d+px\) \{\n([\s\S]*?)\n\}/g), (m) => m[1]);
    expect(blocks.length).toBeGreaterThanOrEqual(3);
    const weight = (sel: string) => (sel.replace(/:not\([^)]*\)/g, "").match(/[.[]/g) || []).length;
    const classes = (sel: string) => new Set(sel.replace(/:not\([^)]*\)|:has\(.*\)|\[[^\]]*\]/g, "").split(".").filter(Boolean));
    let checked = 0;
    for (const b of blocks) {
      const rules = Array.from(b.matchAll(/^\s*([^{\n]+?) \{([^}]*)\}/gm), (m) => ({ sel: m[1], body: m[2] })).filter(
        (r) => r.sel.startsWith(".split") && r.body.includes("grid-template-columns"),
      );
      rules.forEach((r, i) => {
        if (r.sel.includes("[data-w")) return;
        checked++;
        const later = rules.slice(i + 1).filter((l) => /\[data-w\]/.test(l.sel.replace(/:not\(\[data-w\]\)/g, "")));
        const own = classes(r.sel);
        const wins = later.some((l) => [...classes(l.sel)].every((c) => own.has(c)) && weight(l.sel) >= weight(r.sel));
        expect(wins, `${r.sel} sets its columns over a dragged width`).toBe(true);
      });
    }
    expect(checked).toBeGreaterThanOrEqual(5);
  });
});

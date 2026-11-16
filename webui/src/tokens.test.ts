// The web UIs look like the app: every token of tokens.css is the value of
// the same name in the app's theme.slint, light and dark, and the widths
// where the layout changes are the app's.
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

  it("change the layout where the app does", () => {
    const shape = global("Shape");
    const wide = shape.find(([n]) => n === "wide")![1].match(/>= (\d+)px/)![1];
    const large = shape.find(([n]) => n === "large")![1].match(/>= (\d+)px/)![1];
    expect(wide).toBe("1100");
    expect(large).toBe("1800");
    expect(app).toContain(`@media (min-width: ${wide}px)`);
    expect(app).toContain(`@media (max-width: ${Number(wide) - 1}px)`);
    expect(app).toContain(`@media (min-width: ${large}px)`);
  });
});

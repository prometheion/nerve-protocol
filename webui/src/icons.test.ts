// The web UIs draw the app's own icons: src/icons.ts holds each one of
// crates/nerve/ui/icons as the app has it (scripts/icons.mjs writes it).
import { expect, it } from "vitest";
import { ICONS } from "./icons";

const files = import.meta.glob("../../crates/nerve/ui/icons/*.svg", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

function parse(svg: string) {
  const inner = svg.replace(/^[\s\S]*?<svg[^>]*>/, "").replace(/<\/svg>\s*$/, "");
  return Array.from(inner.matchAll(/<(\w+)((?:\s+[\w-]+="[^"]*")*)\s*\/>/g), (m) => [
    m[1],
    Object.fromEntries(Array.from(m[2].matchAll(/([\w-]+)="([^"]*)"/g), (a) => [a[1], a[2]])),
  ]);
}

it("holds every icon of the app as the app has it", () => {
  const names = Object.keys(files).map((f) => f.split("/").pop()!.replace(".svg", "")).filter((n) => n !== "app");
  expect(names.length).toBeGreaterThan(40);
  for (const name of names) {
    expect(ICONS[name], name).toEqual(parse(files[`../../crates/nerve/ui/icons/${name}.svg`]));
  }
});

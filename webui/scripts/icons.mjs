// Writes src/icons.ts from the desktop app's own icons
// (crates/nerve/ui/icons/*.svg, Lucide, ISC licence), so the web UIs draw
// the same ones, as data: each icon is a list of elements, which React
// draws without parsing markup. The few the web UIs need beyond the app's
// (Sign out, the menu, a program) follow. src/icons.test.ts checks that
// the file matches the app's icons.
//
//   node scripts/icons.mjs
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, "../../crates/nerve/ui/icons");

// The elements inside an icon's <svg>: [tag, attributes].
export function parse(svg) {
  const inner = svg.replace(/^[\s\S]*?<svg[^>]*>/, "").replace(/<\/svg>\s*$/, "");
  const out = [];
  for (const m of inner.matchAll(/<(\w+)((?:\s+[\w-]+="[^"]*")*)\s*\/>/g)) {
    const attrs = {};
    for (const a of m[2].matchAll(/([\w-]+)="([^"]*)"/g)) attrs[a[1]] = a[2];
    out.push([m[1], attrs]);
  }
  return out;
}

const EXTRA = {
  bot: '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>',
  menu: '<line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="18" y2="18"/>',
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const icons = {};
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".svg") && f !== "app.svg").sort()) {
    icons[f.slice(0, -4)] = parse(readFileSync(join(dir, f), "utf8"));
  }
  for (const [k, v] of Object.entries(EXTRA)) icons[k] = parse(`<svg>${v}</svg>`);
  const lines = Object.entries(icons).map(([k, v]) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)},`);
  writeFileSync(join(here, "../src/icons.ts"), `// Written by scripts/icons.mjs from crates/nerve/ui/icons: do not edit.
// Lucide icons (ISC licence), as the desktop app has them.
export type IconPart = [string, Record<string, string>];

export const ICONS: Record<string, IconPart[]> = {
${lines.join("\n")}
};

export type IconName = keyof typeof ICONS;
`);
}

// What a node or a center wrote goes into text nodes only: no source of the
// web UIs writes markup from a string, and none sets a style or a script
// inline, which the servers' CSP refuses.
import { expect, it } from "vitest";

const sources = import.meta.glob(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./test/**"], {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

it("builds no markup from text", () => {
  expect(Object.keys(sources).length).toBeGreaterThan(10);
  for (const [file, text] of Object.entries(sources)) {
    for (const sink of ["dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "srcdoc", "eval(", "new Function"]) {
      expect(text.includes(sink), `${file} uses ${sink}`).toBe(false);
    }
    expect(/\sstyle=\{/.test(text), `${file} sets a style inline`).toBe(false);
  }
});

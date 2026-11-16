// Helpers of the page tests: draw a component into the test's DOM
// (happy-dom), act on it as a person does, and find what it shows. Each
// step waits for React to settle (act).
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach } from "vitest";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mounted: Root[] = [];
afterEach(async () => {
  for (const r of mounted.splice(0)) await act(async () => r.unmount());
  document.body.replaceChildren();
  location.hash = "";
});

export async function render(node: ReactNode): Promise<HTMLElement> {
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  mounted.push(root);
  await act(async () => root.render(node));
  await settle();
  return el;
}

/** Lets what the page asked for come in, and React draw it. */
export async function settle(times = 3) {
  for (let i = 0; i < times; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
  }
}

export async function click(target: Element | null | undefined) {
  if (!target) throw new Error("nothing to click");
  await act(async () => {
    (target as HTMLElement).click();
  });
  await settle();
}

/** Types into a field as a person does: the field's value, then its event. */
export async function type(target: Element | null | undefined, text: string) {
  if (!target) throw new Error("nothing to type into");
  const el = target as HTMLInputElement | HTMLTextAreaElement;
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  await act(async () => {
    Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, text);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await settle();
}

export async function key(target: Element, k: string) {
  await act(async () => {
    target.dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true }));
  });
  await settle();
}

const norm = (s: string | null) => (s || "").replace(/\s+/g, " ").trim();

/** The elements matching `sel` whose text is `text` (or matches it). */
export function allByText(root: ParentNode, text: string | RegExp, sel = "*"): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(sel)).filter((e) => {
    const t = norm(e.textContent);
    return typeof text === "string" ? t === text : text.test(t);
  });
}

/** The innermost element matching `sel` with this text; it must be there. */
export function byText(root: ParentNode, text: string | RegExp, sel = "*"): HTMLElement {
  const all = allByText(root, text, sel);
  const inner = all.filter((e) => !all.some((o) => o !== e && e.contains(o)));
  if (!inner.length) throw new Error(`no ${sel} with the text ${text}:\n${norm((root as HTMLElement).textContent || "").slice(0, 2000)}`);
  return inner[0];
}

export function button(root: ParentNode, text: string | RegExp): HTMLButtonElement {
  return byText(root, text, "button, [role=button], a") as HTMLButtonElement;
}

export function text(root: ParentNode): string {
  return norm((root as HTMLElement).textContent);
}

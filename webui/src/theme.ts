// Light or dark: "system" (the default) follows the browser; the choice is
// kept in localStorage. It is applied before the page draws (each entry's
// first import), so the page never shows the wrong theme.

export type ThemeChoice = "system" | "light" | "dark";
const KEY = "nerve.theme";

export function storedTheme(): ThemeChoice {
  try {
    const t = localStorage.getItem(KEY);
    return t === "light" || t === "dark" ? t : "system";
  } catch {
    return "system";
  }
}

function systemDark(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
}

export function applyTheme(choice: ThemeChoice) {
  const dark = choice === "dark" || (choice === "system" && systemDark());
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  const m = document.querySelector('meta[name="theme-color"]') as HTMLMetaElement | null;
  if (m) m.content = dark ? "#0f1116" : "#f4f5f9";
}

export function chooseTheme(choice: ThemeChoice) {
  try {
    localStorage.setItem(KEY, choice);
  } catch {
    /* storage blocked: lasts until the page is left */
  }
  applyTheme(choice);
}

applyTheme(storedTheme());
if (typeof matchMedia === "function") {
  matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", () => {
    if (storedTheme() === "system") applyTheme("system");
  });
}

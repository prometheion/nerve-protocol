// How times, lengths and counts read on the pages.

export function when(ms?: number | null): string {
  return ms ? new Date(ms).toLocaleString() : "never";
}

export function ago(ms?: number | null): string {
  if (!ms) return "never";
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export function duration(ms: number): string {
  const m = Math.round(ms / 60000);
  if (ms < 60000) return `${Math.round(ms / 1000)} s`;
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  return h < 48 ? `${h} h ${m % 60} min` : `${Math.floor(h / 24)} d ${h % 24} h`;
}

export function plural(n: number, one: string, many?: string): string {
  return `${n} ${n === 1 ? one : many || one + "s"}`;
}

/** A log entry's time: the time of day today, with the date before. */
export function clock(ms: number): string {
  const d = new Date(ms);
  const t = d.toLocaleTimeString(undefined, { hourCycle: "h23" });
  return d.toDateString() === new Date().toDateString() ? t : `${d.toLocaleDateString()} ${t}`;
}

export const gb = (bytes: number) => `${(bytes / 1e9).toFixed(1)} GB`;

/** A rule as `rule` prints it: its tab, carriage return and line feed
 * written `\t`, `\r` and `\n`. A one-line field would drop a real line
 * break, and with it the rule's meaning. */
export const escapeControls = (rule: string) => rule.replace(/[\t\r\n]/g, (c) => (c === "\t" ? "\\t" : c === "\r" ? "\\r" : "\\n"));

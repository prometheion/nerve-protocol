// The API of the center and the node, as their servers answer it
// (docs/dev/web-uis.md). A session is the token the login answered: this
// tab keeps it in sessionStorage and sends it as a header with every call,
// never as a cookie, so no other page or port of this browser's host gets
// it. A 401 sends the tab back to the login.

export const SESSION_KEY = "nerve.session";
export const SESSION_HEADER = "X-Nerve-Session";

/** What a call that failed says: the server's reason, its status and body. */
export class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;
  /** The session ended: the page goes to the login, and says nothing more. */
  auth: boolean;

  constructor(message: string, status: number, body: Record<string, unknown>, auth = false) {
    super(message);
    this.status = status;
    this.body = body;
    this.auth = auth;
  }
}

export function storedSession(): string | null {
  try {
    return sessionStorage.getItem(SESSION_KEY);
  } catch {
    return null;
  }
}

export function keepSession(s: string | null) {
  try {
    if (s) sessionStorage.setItem(SESSION_KEY, s);
    else sessionStorage.removeItem(SESSION_KEY);
  } catch {
    /* storage blocked: this page holds it until it is left */
  }
}

/** Where the tab goes when its session has ended; a test replaces it. */
export const nav = {
  toLogin() {
    location.assign("/login");
  },
};

function headers(): Record<string, string> {
  return { [SESSION_HEADER]: storedSession() || "" };
}

async function json(r: Response): Promise<Record<string, unknown>> {
  try {
    const v = await r.json();
    return v && typeof v === "object" ? v : {};
  } catch {
    return {};
  }
}

function ended(): ApiError {
  keepSession(null);
  nav.toLogin();
  return new ApiError("Your session ended. Sign in again.", 401, {}, true);
}

/** One API call; a POST sends `body` as JSON. */
export async function api<T = any>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, headers: headers() };
  if (method === "POST") {
    (init.headers as Record<string, string>)["Content-Type"] = "application/json";
    init.body = JSON.stringify(body ?? {});
  }
  const r = await fetch(path, init);
  const v = await json(r);
  if (r.status === 401) throw ended();
  if (!r.ok) {
    const data = v.data as { field?: string } | undefined;
    const why = data && data.field ? ` (${data.field})` : "";
    const code = v.code ? ` [${v.code}]` : "";
    throw new ApiError(String(v.error || r.statusText || `error ${r.status}`) + code + why, r.status, v);
  }
  return v as T;
}

/** Whether this tab is signed in; the login when it is not. */
export async function startSession(): Promise<boolean> {
  const r = await fetch("/api/session", { headers: headers() });
  const s = await json(r);
  if (!r.ok || !s.logged_in) {
    keepSession(null);
    nav.toLogin();
    return false;
  }
  return true;
}

/** Signs out: the server ends the session and this tab forgets it. */
export async function signOut() {
  try {
    await fetch("/logout", { method: "POST", headers: headers() });
  } catch {
    /* the server is gone: its sessions went with it */
  }
  keepSession(null);
  nav.toLogin();
}

/** A file the server sends, saved by the browser: the session goes as a
 * header, which a plain link cannot send. */
export async function download(path: string, name: string) {
  const r = await fetch(path, { headers: headers() });
  if (r.status === 401) throw ended();
  if (!r.ok) {
    const v = await json(r);
    throw new ApiError(String(v.error || r.statusText), r.status, v);
  }
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.hidden = true;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** The user guide of this release (`<meta name="nerve-guide">`, which the
 * server fills), `main` where the page does not say. */
export function guide(): string {
  const meta = document.querySelector('meta[name="nerve-guide"]') as HTMLMetaElement | null;
  const at = meta && /^[\w.-]+$/.test(meta.content) ? meta.content : "main";
  return `https://github.com/prometheion/nerve-protocol/tree/${at}/docs/user`;
}

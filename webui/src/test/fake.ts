// A fake server for the page tests: answers the API calls a page makes from
// a table of handlers, and records each call. A handler returns the JSON
// body, or throws `refuse(status, body)`.
import { vi } from "vitest";

export type Call = { method: string; path: string; query: URLSearchParams; body: Record<string, unknown> };
type Handler = (call: Call) => unknown;

export class Refusal {
  constructor(
    public status: number,
    public body: Record<string, unknown>,
  ) {}
}

export const refuse = (status: number, error: string, more: Record<string, unknown> = {}) => new Refusal(status, { error, ...more });

export function fakeServer(routes: Record<string, Handler>) {
  const calls: Call[] = [];
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://127.0.0.1:7480");
    const method = (init?.method || "GET").toUpperCase();
    let body: Record<string, unknown> = {};
    if (typeof init?.body === "string" && init.body) body = JSON.parse(init.body);
    const call = { method, path: url.pathname, query: url.searchParams, body };
    calls.push(call);
    const h = routes[`${method} ${url.pathname}`];
    if (!h) return new Response(JSON.stringify({ error: "unknown API call" }), { status: 404 });
    try {
      const v = await h(call);
      if (v instanceof Response) return v;
      return new Response(JSON.stringify(v ?? {}), { status: 200, headers: { "Content-Type": "application/json" } });
    } catch (e) {
      if (e instanceof Refusal) return new Response(JSON.stringify(e.body), { status: e.status });
      throw e;
    }
  });
  vi.stubGlobal("fetch", fetch);
  return {
    calls,
    /** The calls of `method path`, oldest first. */
    to: (method: string, path: string) => calls.filter((c) => c.method === method && c.path === path),
  };
}

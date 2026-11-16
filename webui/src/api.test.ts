// The API client: the session goes as a header, never as a cookie; a 401
// sends the tab to the login; a refusal says the server's reason.
import { beforeEach, expect, it, vi } from "vitest";
import { ApiError, SESSION_KEY, api, guide, nav, startSession } from "./api";
import { fakeServer, refuse } from "./test/fake";

beforeEach(() => {
  sessionStorage.clear();
  vi.spyOn(nav, "toLogin").mockImplementation(() => {});
});

it("sends the tab's session as a header and the body as JSON", async () => {
  sessionStorage.setItem(SESSION_KEY, "s1");
  const f = fakeServer({ "POST /api/pair": (c) => ({ got: c.body }) });
  expect(await api("POST", "/api/pair", { a: 1 })).toEqual({ got: { a: 1 } });
  const init = vi.mocked(fetch).mock.calls[0][1]!;
  const h = init.headers as Record<string, string>;
  expect(h["X-Nerve-Session"]).toBe("s1");
  expect(h["Content-Type"]).toBe("application/json");
  expect(init.credentials).toBeUndefined();
  expect(f.to("POST", "/api/pair")).toHaveLength(1);
});

it("goes to the login when the session has ended, and forgets it", async () => {
  sessionStorage.setItem(SESSION_KEY, "old");
  fakeServer({ "GET /api/overview": () => { throw refuse(401, "log in first"); } });
  const e = await api("GET", "/api/overview").catch((e) => e);
  expect(e).toBeInstanceOf(ApiError);
  expect(e.auth).toBe(true);
  expect(nav.toLogin).toHaveBeenCalled();
  expect(sessionStorage.getItem(SESSION_KEY)).toBeNull();
});

it("says a refusal's reason, its code and the field", async () => {
  fakeServer({
    "POST /api/caps/save": () => {
      throw refuse(409, "the machine refused", { code: "bad_args", data: { field: "name" }, errors: { name: "taken" } });
    },
  });
  const e = (await api("POST", "/api/caps/save").catch((e) => e)) as ApiError;
  expect(e.message).toBe("the machine refused [bad_args] (name)");
  expect(e.status).toBe(409);
  expect(e.body.errors).toEqual({ name: "taken" });
  expect(e.auth).toBe(false);
});

it("asks whether the tab is signed in before the page draws", async () => {
  fakeServer({ "GET /api/session": () => ({ login: true, logged_in: false }) });
  expect(await startSession()).toBe(false);
  expect(nav.toLogin).toHaveBeenCalled();
  fakeServer({ "GET /api/session": () => ({ login: true, logged_in: true }) });
  expect(await startSession()).toBe(true);
});

it("replaces the page with the login when the tab is not signed in, so Back does not loop", async () => {
  vi.mocked(nav.toLogin).mockRestore();
  const replace = vi.spyOn(location, "replace").mockImplementation(() => {});
  const assign = vi.spyOn(location, "assign").mockImplementation(() => {});
  fakeServer({ "GET /api/session": () => ({ login: true, logged_in: false }) });
  expect(await startSession()).toBe(false);
  expect(replace).toHaveBeenCalledWith("/login");
  expect(assign).not.toHaveBeenCalled();
  replace.mockRestore();
  assign.mockRestore();
});

it("links the user guide of this release", () => {
  const m = document.createElement("meta");
  m.name = "nerve-guide";
  m.content = "v0.1.0";
  document.head.append(m);
  expect(guide()).toBe("https://github.com/prometheion/nerve-protocol/tree/v0.1.0/docs/user");
  m.content = "{{GUIDE_REF}}";
  expect(guide()).toBe("https://github.com/prometheion/nerve-protocol/tree/main/docs/user");
  m.remove();
});

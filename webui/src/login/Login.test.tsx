import { act } from "react";
import { beforeEach, expect, it, vi } from "vitest";
import { SESSION_KEY } from "../api";
import { click, render, text } from "../test/dom";
import { fakeServer, refuse } from "../test/fake";
import { Login, go, readInfo } from "./Login";

beforeEach(() => {
  sessionStorage.clear();
  vi.spyOn(go, "home").mockImplementation(() => {});
});

const info = { secret: "Owner token", title: "Log in to this center", tagline: "One center for all your machines.", command: "sudo nerve-center owner-token", after: " shows its owner token." };

it("posts what is in the field, keeps the session in this tab and opens the page", async () => {
  const f = fakeServer({ "POST /login": (c) => (c.body.token === "t0k" ? { session: "s9" } : null) });
  const el = await render(<Login info={info} />);
  expect(text(el)).toContain("sudo nerve-center owner-token shows its owner token.");
  // As a script or a password manager fills it: no input event.
  (el.querySelector(".login-input") as HTMLInputElement).value = "t0k";
  await click(el.querySelector(".login-submit"));
  expect(f.to("POST", "/login")[0].body).toEqual({ token: "t0k" });
  expect(sessionStorage.getItem(SESSION_KEY)).toBe("s9");
  expect(go.home).toHaveBeenCalled();
  expect(document.cookie).toBe("");
});

it("says why a token is refused", async () => {
  fakeServer({ "POST /login": () => { throw refuse(401, "Wrong owner token. `nerve-center owner-token` shows it."); } });
  const el = await render(<Login info={info} />);
  (el.querySelector(".login-input") as HTMLInputElement).value = "nope";
  await click(el.querySelector(".login-submit"));
  const err = el.querySelector("#login-error") as HTMLElement;
  expect(err.hidden).toBe(false);
  expect(err.textContent).toContain("Wrong owner token.");
  expect(go.home).not.toHaveBeenCalled();
  expect(sessionStorage.getItem(SESSION_KEY)).toBeNull();
});

it("reads its words from the page as data", () => {
  const m = document.createElement("meta");
  m.name = "nerve-login";
  m.content = JSON.stringify({ ...info, tagline: "<b>x</b>" });
  document.head.append(m);
  expect(readInfo().tagline).toBe("<b>x</b>");
  m.content = "{{LOGIN}}";
  expect(readInfo().secret).toBe("Token");
  m.remove();
});

it("is ready again when the browser shows it from its cache after a sign-in", async () => {
  fakeServer({ "POST /login": () => ({ session: "s9" }) });
  const el = await render(<Login info={info} />);
  (el.querySelector(".login-input") as HTMLInputElement).value = "t0k";
  await click(el.querySelector(".login-submit"));
  const submit = el.querySelector(".login-submit") as HTMLButtonElement;
  expect(submit.disabled).toBe(true);
  await act(async () => {
    window.dispatchEvent(new Event("pageshow"));
  });
  expect(submit.disabled).toBe(false);
  expect(text(submit)).toBe("Log in");
});

// Page tests of the node's web UI against a fake server.
import { describe, expect, it, vi } from "vitest";
import { nav } from "../api";
import { node } from "../test/apps";
import { allByText, button, click, settle, text, type } from "../test/dom";

describe("Overview", () => {
  it("asks before a panic, then sends the tab to the login", async () => {
    const out = vi.spyOn(nav, "toLogin").mockImplementation(() => {});
    const { el, f } = await node("overview", { "POST /api/panic": () => ({}) });
    await click(button(el, "Panic"));
    await click(button(document.querySelector("[role=dialog]")!, "Cancel"));
    await settle(4);
    expect(f.to("POST", "/api/panic")).toHaveLength(0);
    await click(button(el, "Panic"));
    await click(button(document.querySelector("[role=dialog]")!, "Panic"));
    await settle(4);
    expect(f.to("POST", "/api/panic")).toHaveLength(1);
    expect(out).toHaveBeenCalled();
  });
});

describe("Centers", () => {
  it("asks before it grants a center its settings, and unpairs only on yes in the row", async () => {
    const { el, f } = await node("centers", { "POST /api/centers/settings": () => ({}), "POST /api/centers/remove": () => ({}) });
    await click(allByText(el, /^lab/, ".lrow")[0]);
    await click(el.querySelector(".dcol [role=switch]"));
    await click(button(document.querySelector("[role=dialog]")!, "Cancel"));
    await settle(4);
    expect(f.to("POST", "/api/centers/settings")).toHaveLength(0);
    await click(el.querySelector(".dcol [role=switch]"));
    await click(button(document.querySelector("[role=dialog]")!, "Grant"));
    await settle(4);
    expect(f.to("POST", "/api/centers/settings")[0].body).toEqual({ center: "lab", state: "on" });
    await click(button(el, "Unpair"));
    expect(text(el)).toContain("Unpair lab?");
    await click(el.querySelector(".ask .btn.danger-solid"));
    expect(f.to("POST", "/api/centers/remove")[0].body).toEqual({ center: "lab" });
  });

  it("pairs from a link pasted in the overlay", async () => {
    const { el, f } = await node("centers", { "POST /api/centers/pair": () => ({ url: "https://center.example.net", name: "work" }) });
    await click(button(el, "Pair a center"));
    const d = document.querySelector("[role=dialog]")!;
    await type(d.querySelector("input[placeholder='nerve://pair?…']"), "nerve://pair?center=x&code=y");
    await type(d.querySelector("input[placeholder='home']"), "work");
    await click(button(d, "Pair"));
    expect(f.to("POST", "/api/centers/pair")[0].body).toEqual({ link: "nerve://pair?center=x&code=y", name: "work" });
    expect(document.querySelector("[role=dialog]")).toBeNull();
  });
});

describe("Permissions", () => {
  it("switches a folder's rights in its row; Write reads too", async () => {
    const { el, f } = await node("permissions", { "POST /api/folders/add": () => ({}) });
    const docs = allByText(el, /^\/home\/alex\/Documents/, ".prow")[0];
    await click(button(docs, "Write"));
    expect(f.to("POST", "/api/folders/add")[0].body).toEqual({ center: "home", path: "/home/alex/Documents", read: true, write: true, execute: false });
  });

  it("takes Write away with Read, and gives Read with Write", async () => {
    const { el, f } = await node("permissions", { "POST /api/folders/add": () => ({}) });
    await click(button(allByText(el, /^\/home\/alex\/projects\/site/, ".prow")[0], "Read"));
    expect(f.to("POST", "/api/folders/add")[0].body).toEqual({ center: "home", path: "/home/alex/projects/site", read: false, write: false, execute: true });
    await click(button(el, "Add a folder…"));
    const form = el.querySelector(".prow.form")!;
    await type(form.querySelector("input"), "/srv/a");
    await click(button(form, "Read"));
    await click(button(form, "Write"));
    await click(button(form, "Save"));
    expect(f.to("POST", "/api/folders/add")[1].body).toEqual({ center: "home", path: "/srv/a", read: true, write: true, execute: false });
  });

  it("adds a folder in a form row of the list", async () => {
    const { el, f } = await node("permissions", { "POST /api/folders/add": () => ({}) });
    await click(button(el, "Add a folder…"));
    await type(el.querySelector(".prow.form input"), "/srv/www");
    await click(button(el.querySelector(".prow.form")!, "Run"));
    await click(button(el.querySelector(".prow.form")!, "Save"));
    expect(f.to("POST", "/api/folders/add")[0].body).toEqual({ center: "home", path: "/srv/www", read: true, write: false, execute: true });
  });

  it("says the guard's limit unfolded, and adds a rule as a wildcard", async () => {
    const { el, f } = await node("permissions", { "POST /api/rules/add": () => ({}) });
    await click(button(el.querySelector(".pnav")!, /^Forbidden commands/));
    const guard = allByText(el, /a built-in guard catches mistakes, not someone who hides the name\.$/, "p")[0];
    expect(guard.closest("details")).toBeNull();
    await click(button(el, "Add a forbidden command…"));
    await type(el.querySelector(".prow.form input"), "git push");
    await click(el.querySelector(".prow.form [role=switch]"));
    await click(button(el.querySelector(".prow.form")!, "Save"));
    expect(f.to("POST", "/api/rules/add")[0].body).toEqual({ center: "home", list: "deny", rule: "git push", wildcard: true });
  });

  it("sets a mode for some hours", async () => {
    const { el, f } = await node("permissions", { "POST /api/mode": () => ({}) });
    await click(button(el, "User"));
    await type(el.querySelector("input[aria-label='For hours']"), "2");
    await click(button(el, "Set the mode"));
    expect(f.to("POST", "/api/mode")[0].body).toEqual({ center: "home", mode: "user", hours: 2, as_owner: false });
  });
});

describe("Capabilities", () => {
  it("switches an action for the chosen center in its row", async () => {
    const { el, f } = await node("capabilities", { "POST /api/caps/set": () => ({}) });
    const row = allByText(el, /^fs\.read/, ".lrow")[0];
    await click(button(row, "Hidden"));
    expect(f.to("POST", "/api/caps/set")[0].body).toEqual({ center: "home", cap: "fs.read", setting: "hidden" });
  });
});

describe("Audit", () => {
  it("shows the rule as it will be stored before it adds it", async () => {
    const { el, f } = await node("audit", { "POST /api/audit/rule": () => ({}) });
    await click(allByText(el, /git push --force/, ".lrow")[0]);
    await click(button(el, "Allow as wildcard"));
    await click(button(document.querySelector("[role=dialog]")!, "Cancel"));
    await settle(4);
    expect(f.to("POST", "/api/audit/rule")).toHaveLength(0);
    await click(button(el, "Allow as wildcard"));
    expect(text(document.querySelector("[role=dialog]")!)).toContain("as it will be stored: exec.run:git push *");
    await click(button(document.querySelector("[role=dialog]")!, "Add"));
    await settle(4);
    expect(f.to("POST", "/api/audit/rule")[0].body).toMatchObject({ center: "home", list: "allow", wildcard: true });
  });
});

describe("every page", () => {
  it("says its subtitles and notes in one short line", async () => {
    for (const p of ["overview", "centers", "relay", "permissions", "capabilities", "audit", "log", "settings", "help"]) {
      const { el } = await node(p);
      expect(el.querySelector("#top-title"), p).not.toBeNull();
      for (const s of el.querySelectorAll(".phead .sub, .sechead p, .lnote, .prow.note")) {
        expect(text(s).length, `${p}: ${text(s)}`).toBeLessThanOrEqual(120);
      }
    }
  });
});

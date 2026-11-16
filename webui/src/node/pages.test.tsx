// Page tests of the node's web UI against a fake server.
import { act } from "react";
import { describe, expect, it, vi } from "vitest";
import { nav } from "../api";
import { node } from "../test/apps";
import { nodeData } from "../test/fixtures";
// The app's Permissions page, which says the same words.
import appPermissions from "../../../crates/nerve/ui/permissions.slint?raw";
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

describe("Overview, locked", () => {
  it("unlocks the node without asking", async () => {
    const d = nodeData();
    d.overview.locked = true;
    const { el, f } = await node("overview", { "GET /api/overview": () => d.overview, "POST /api/unlock": () => ({}) });
    expect(text(el)).toContain("The node is locked");
    expect(allByText(el, "Panic", "button")).toHaveLength(0);
    await click(button(el, "Unlock"));
    expect(document.querySelector("[role=dialog]")).toBeNull();
    expect(f.to("POST", "/api/unlock")).toHaveLength(1);
  });
});

describe("Relay", () => {
  it("adds a node with a link shown once, makes it a new link, and removes it after asking in place", async () => {
    const { el, f } = await node("relay", {
      "POST /api/relay/add": () => ({ token: { node: "lab-pc-2", link: "https://lab-pc-2:secret@relay.example:7490" } }),
      "POST /api/relay/token": () => ({ token: { node: "laptop-2", link: "https://laptop-2:fresh@relay.example:7490" } }),
      "POST /api/relay/remove": () => ({}),
    });
    await click(button(el, "Add a node…"));
    await type(el.querySelector(".dcol input[placeholder='lab-pc']"), "lab-pc-2");
    await click(button(el, "Make the link"));
    expect(f.to("POST", "/api/relay/add").map((c) => c.body)).toEqual([{ name: "lab-pc-2" }]);
    expect(text(el)).toContain("The link for lab-pc-2, shown once: https://lab-pc-2:secret@relay.example:7490");
    await click(allByText(el, /^laptop-2/, ".lrow")[0]);
    await click(button(el, "New link"));
    expect(f.to("POST", "/api/relay/token").map((c) => c.body)).toEqual([{ name: "laptop-2" }]);
    expect(text(el)).toContain("https://laptop-2:fresh@relay.example:7490");
    await click(button(el.querySelector(".dcol")!, "Remove"));
    expect(f.to("POST", "/api/relay/remove")).toHaveLength(0);
    await click(el.querySelector(".ask .btn.danger-solid"));
    expect(f.to("POST", "/api/relay/remove").map((c) => c.body)).toEqual([{ name: "laptop-2" }]);
  });

  it("connects through a relay and empties its password field", async () => {
    const { el, f } = await node("relay", { "POST /api/proxy/set": () => ({}) });
    const d = el.querySelector(".dcol")!;
    await type(d.querySelector("input[placeholder^='https://']"), "https://lab-pc@relay.example:7490");
    const pw = d.querySelector("input[type=password]") as HTMLInputElement;
    await type(pw, "s3cret");
    await click(button(d, "Connect"));
    expect(f.to("POST", "/api/proxy/set").map((c) => c.body)).toEqual([{ url: "https://lab-pc@relay.example:7490", password: "s3cret" }]);
    expect(pw.value).toBe("");
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

  it("opens the pages of the center picked, not of the first", async () => {
    const { el, f } = await node("centers", { "POST /api/mode": () => ({}) });
    await click(allByText(el, /^lab/, ".lrow")[0]);
    await click(el.querySelector(".dcol a.btn.sm"));
    await settle(4);
    await click(button(el, "Folder"));
    await click(button(el, "Set the mode"));
    expect(f.to("POST", "/api/mode")[0].body).toMatchObject({ center: "lab", mode: "folder" });
  });

  it("does not carry an open Unpair question to the next center picked", async () => {
    const { el } = await node("centers", { "POST /api/centers/remove": () => ({}) });
    await click(button(el, "Unpair"));
    expect(text(el)).toContain("Unpair home?");
    await click(allByText(el, /^lab/, ".lrow")[0]);
    expect(text(el)).not.toContain("Unpair lab?");
    expect(el.querySelector(".ask")).toBeNull();
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
    // The node keeps only the program: the switch says so.
    expect(text(el.querySelector(".prow.form [role=switch]")!.closest(".pl2")!)).toContain("Wildcard: every command of this program");
    expect(appPermissions).toContain('"Wildcard: every command of this program"');
    await click(el.querySelector(".prow.form [role=switch]"));
    await click(button(el.querySelector(".prow.form")!, "Save"));
    expect(f.to("POST", "/api/rules/add")[0].body).toEqual({ center: "home", list: "deny", rule: "git push", wildcard: true });
  });

  it("edits a rule in its place from the entry as listed, and sends nothing while it is unchanged", async () => {
    const { el, f } = await node("permissions", { "POST /api/rules/edit": () => ({}), "POST /api/rules/add": () => ({}), "POST /api/rules/remove": () => ({}) });
    await click(button(el.querySelector(".pnav")!, /^Forbidden commands/));
    await click(allByText(el, "exec.run:git push --force origin main", ".prow")[0].querySelector("button[aria-label=Edit]"));
    const form = el.querySelector(".prow.form")!;
    const field = form.querySelector("input")!;
    expect(field.value).toBe("exec.run:git push --force origin main");
    expect(form.querySelector("[role=switch]")).toBeNull();
    const save = button(form, "Save");
    expect(save.disabled).toBe(true);
    await click(save);
    await type(field, " exec.run:git push --force origin main ");
    expect(button(form, "Save").disabled).toBe(true);
    await click(button(form, "Save"));
    expect(f.to("POST", "/api/rules/edit")).toHaveLength(0);
    await type(field, "git push --force");
    await click(button(form, "Save"));
    expect(f.to("POST", "/api/rules/edit").map((c) => c.body)).toEqual([{ center: "home", list: "deny", rule: "exec.run:git push --force origin main", new: "git push --force" }]);
    expect(f.to("POST", "/api/rules/add")).toHaveLength(0);
    expect(f.to("POST", "/api/rules/remove")).toHaveLength(0);
  });

  it("edits a rule with a line break in the form `rule` prints it", async () => {
    const d = nodeData();
    d.perm.rules.deny.push("exec.run:cat <<EOF > /etc/x\n*");
    const { el, f } = await node("permissions", { "GET /api/perm": () => d.perm, "POST /api/rules/edit": () => ({}) });
    await click(button(el.querySelector(".pnav")!, /^Forbidden commands/));
    // Listed as `rule` prints it, on one line.
    const row = allByText(el, "exec.run:cat <<EOF > /etc/x\\n*", ".prow")[0];
    await click(row.querySelector("button[aria-label=Edit]"));
    const field = el.querySelector(".prow.form input")!;
    expect((field as HTMLInputElement).value).toBe("exec.run:cat <<EOF > /etc/x\\n*");
    await type(field, "exec.run:cat <<EOF > /etc/y\\n*");
    await click(button(el.querySelector(".prow.form")!, "Save"));
    expect(f.to("POST", "/api/rules/edit").map((c) => c.body)).toEqual([
      { center: "home", list: "deny", rule: "exec.run:cat <<EOF > /etc/x\\n*", new: "exec.run:cat <<EOF > /etc/y\\n*" },
    ]);
  });

  it("sets a mode for some hours", async () => {
    const { el, f } = await node("permissions", { "POST /api/mode": () => ({}) });
    await click(button(el, "User"));
    await type(el.querySelector("input[aria-label='For hours']"), "2");
    await click(button(el, "Set the mode"));
    expect(f.to("POST", "/api/mode")[0].body).toEqual({ center: "home", mode: "user", hours: 2, as_owner: false });
  });

  it("leaves allowlist mode as the owner for another mode without as the owner", async () => {
    const d = nodeData();
    Object.assign(d.overview.centers[0], { mode: "allowlist", as_owner: true });
    const { el, f } = await node("permissions", { "GET /api/overview": () => d.overview, "POST /api/mode": () => ({}) });
    expect((el.querySelector("label.check input") as HTMLInputElement).checked).toBe(true);
    await click(button(el, "Folder"));
    await click(button(el, "Set the mode"));
    expect(f.to("POST", "/api/mode")[0].body).toEqual({ center: "home", mode: "folder", as_owner: false });
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

describe("Audit, while entries come in", () => {
  it("keeps the entry its details show while newer ones come in", async () => {
    const d = nodeData();
    const { el, f } = await node("audit", { "GET /api/audit": () => d.audit, "POST /api/audit/rule": () => ({}) });
    expect(text(el.querySelector(".dcol")!)).toContain("git push --force origin main");
    const newer = { ...d.audit.entries[1], ts: Date.now(), target: "rm -rf /srv", rule_preview: "rm -rf /srv" };
    d.audit.entries = [...d.audit.entries, newer] as typeof d.audit.entries;
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await settle(4);
    expect(allByText(el, /rm -rf \/srv/, ".lrow")).toHaveLength(1);
    await click(button(el.querySelector(".dcol")!, "Allow"));
    await click(button(document.querySelector("[role=dialog]")!, "Add"));
    await settle(4);
    expect(f.to("POST", "/api/audit/rule")[0].body).toMatchObject({ target: "git push --force origin main" });
  });
});

describe("Audit, once the picked entry is gone from the answer", () => {
  it("keeps the picked entry and acts on it", async () => {
    const d = nodeData();
    const { el, f } = await node("audit", { "GET /api/audit": () => d.audit, "POST /api/audit/rule": () => ({}) });
    await click(allByText(el, /git push --force/, ".lrow")[0]);
    // 600 newer entries: the answer holds 500, so the picked one is gone.
    const base = Date.now();
    const newer = Array.from({ length: 600 }, (_, i) => ({ ts: base + i, center: "home", cap: "fs", action: "read", target: `/srv/f${i}`, decision: "allowed" }));
    d.audit.entries = [...d.audit.entries, ...newer].slice(-500) as typeof d.audit.entries;
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await settle(4);
    expect(allByText(el, /git push --force/, ".lrow")).toHaveLength(0);
    expect(text(el.querySelector(".dcol")!)).toContain("git push --force origin main");
    await click(button(el.querySelector(".dcol")!, "Allow"));
    await click(button(document.querySelector("[role=dialog]")!, "Add"));
    await settle(4);
    expect(f.to("POST", "/api/audit/rule")[0].body).toMatchObject({ target: "git push --force origin main" });
  });

  it("shows the newest again when a search no longer lets the picked entry through", async () => {
    const { el } = await node("audit");
    await click(allByText(el, /git push --force/, ".lrow")[0]);
    expect(text(el.querySelector(".dcol")!)).toContain("git push --force origin main");
    await type(el.querySelector("input[aria-label='Find in target and reason']"), "README");
    expect(text(el.querySelector(".dcol")!)).toContain("README.md");
    expect(text(el.querySelector(".dcol")!)).not.toContain("git push --force");
  });

  it("tells apart the same call twice in one millisecond", async () => {
    const d = nodeData();
    const one = { ...d.audit.entries[1], ts: 1 };
    d.audit.entries = [{ ...one }, { ...one, reason: "the second call" }] as typeof d.audit.entries;
    const { el } = await node("audit", { "GET /api/audit": () => d.audit });
    const rows = allByText(el, /git push --force/, ".lrow");
    expect(rows).toHaveLength(2);
    // Newest first: the second call is the first row.
    await click(rows[1]);
    expect(rows[1].getAttribute("aria-current")).toBe("true");
    expect(rows[0].getAttribute("aria-current")).toBeNull();
    expect(text(el.querySelector(".dcol")!)).not.toContain("the second call");
    await click(rows[0]);
    expect(text(el.querySelector(".dcol")!)).toContain("the second call");
  });
});

describe("Log", () => {
  it("shows the problems only, finds in the lines, and clears after asking", async () => {
    const { el, f } = await node("log", { "POST /api/log/clear": () => ({}) });
    await click(button(el, "Problems"));
    expect(f.to("GET", "/api/log").at(-1)!.query.get("problems")).toBe("1");
    await type(el.querySelector("input[aria-label='Search the messages']"), "time limit");
    expect(el.querySelectorAll(".lrow")).toHaveLength(1);
    expect(text(el.querySelector(".dcol")!)).toContain("a command of home was stopped at its time limit");
    await click(button(el, "Clear"));
    await click(button(document.querySelector("[role=dialog]")!, "Cancel"));
    await settle(4);
    expect(f.to("POST", "/api/log/clear")).toHaveLength(0);
    await click(button(el, "Clear"));
    await click(button(document.querySelector("[role=dialog]")!, "Clear"));
    await settle(4);
    expect(f.to("POST", "/api/log/clear")).toHaveLength(1);
  });
});

describe("Settings", () => {
  it("saves the machine's name as TOML, and revokes a web UI token after asking in place", async () => {
    const { el, f } = await node("settings", { "POST /api/settings/set": () => ({}), "POST /api/ui/revoke": () => ({}) });
    await type(el.querySelector(".dcol input"), 'work "station"');
    await click(button(el.querySelector(".dcol")!, "Save"));
    expect(f.to("POST", "/api/settings/set").map((c) => c.body)).toEqual([{ key: "node.name", value: '"work \\"station\\""' }]);
    await click(allByText(el, /^Web UI/, ".lrow")[0]);
    await click(button(el.querySelector(".dcol")!, "Revoke"));
    expect(text(el)).toContain("Revoke laptop?");
    expect(f.to("POST", "/api/ui/revoke")).toHaveLength(0);
    await click(el.querySelector(".ask .btn.danger-solid"));
    expect(f.to("POST", "/api/ui/revoke").map((c) => c.body)).toEqual([{ label: "laptop" }]);
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

// Page tests of the center's web UI against a fake server: what each page
// shows and what each action sends, as a person uses them.
import { act } from "react";
import { describe, expect, it, vi } from "vitest";
import { center } from "../test/apps";
import { allByText, button, click, settle, text, type } from "../test/dom";
import { refuse } from "../test/fake";
import { centerData } from "../test/fixtures";
import { sudoRuleLine } from "./lines";

const pairing = { link: "nerve://pair?center=x&code=abc&pin=p", code: "abc", expires_ms: Date.now() + 9e5, pin: "p" };

describe("Pair a machine", () => {
  it("offers the command and the bare link, and closes once a machine used the code", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let open = true;
    const { el, f } = await center("nodes", {
      "POST /api/pair": () => pairing,
      "POST /api/pair/status": () => (open ? { open: true } : { open: false, node: { name: "laptop", platform: "linux" } }),
    });
    await click(button(el, "Pair a machine"));
    const dialog = document.querySelector("[role=dialog]")!;
    // Two rows with a Copy each: the command, which reads the link from
    // stdin so that it is never in the process list (#198), and the link
    // alone; a Windows machine opens the link.
    expect(text(dialog)).toContain("nerve-node center add -");
    expect(text(dialog)).toContain(pairing.link);
    expect(text(dialog)).toContain("then paste the link on the next line");
    expect(text(dialog)).toContain("On a Windows machine, open the link on the machine");
    expect(text(dialog)).not.toContain("Certificate pin");
    open = false;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100);
    });
    await settle();
    expect(document.querySelector("[role=dialog]")).toBeNull();
    expect(f.to("POST", "/api/pair/status")[0].body).toEqual({ code: "abc" });
    // It names the machine the center says, and its next step.
    expect(text(el)).toContain("laptop is paired");
    expect(text(el)).toContain("nerve-node folder add ~/project rwx");
    vi.useRealTimers();
  });
});

describe("Nodes", () => {
  it("shows what the center left out of a machine, and asks in the row before a removal", async () => {
    const { el, f } = await center("nodes", { "POST /api/nodes/remove": () => ({}) });
    expect(text(el)).toContain("Not offered to the agent");
    expect(text(el)).toContain("desk.click its arguments schema has oneOf");
    await click(button(el, "Remove"));
    expect(text(el)).toContain("Remove dev? It has to be paired again to come back.");
    expect(f.to("POST", "/api/nodes/remove")).toHaveLength(0);
    await click(el.querySelector(".ask .btn.danger-solid"));
    expect(f.to("POST", "/api/nodes/remove")[0].body).toEqual({ id: "n-dev" });
  });

  it("sends a Windows machine's owner to the Nerve app for its folder", async () => {
    const d = centerData();
    d.overview.nodes = d.overview.nodes.filter((n) => n.platform === "windows").map((n) => ({ ...n, folders: 0 }));
    d.overview.sessions = [];
    const { el } = await center("overview", { "GET /api/overview": () => d.overview });
    expect(text(el)).toContain("2. Give it a folder: in the Nerve app on that machine, Permissions › Folders");
    expect(text(el)).not.toContain("nerve-node folder add");
  });
});

describe("Statistics", () => {
  it("lists all machines and each one, and shows the picked one's numbers", async () => {
    const { el } = await center("stats");
    expect(text(el)).toContain("Kept for 30 days.");
    expect(text(el)).toMatch(/1[.,]712 calls/);
    await click(allByText(el, /^office-pc/, ".lrow")[0]);
    const detail = el.querySelector(".dcol")!;
    expect(text(detail)).toContain("office-pc");
    expect(text(detail)).toContain("exec.run");
  });
});

describe("Harnesses", () => {
  it("shows a token made for Connect a harness once, with the JSON to paste", async () => {
    const { el, f } = await center("harnesses", { "POST /api/tokens/create": () => ({ id: "t9", token: "nrv_secret" }) });
    await click(button(el, "Make a token"));
    expect(f.to("POST", "/api/tokens/create")[0].body).toEqual({ label: "harness" });
    expect(text(el)).toContain('"Authorization":"Bearer nrv_secret"');
    expect(text(el)).toContain("Shown only now.");
    await click(button(el, "Hide the token"));
    expect(text(el)).not.toContain("nrv_secret");
  });
});

describe("Audit", () => {
  it("pins an argument of the call for a rule on the machine", async () => {
    const { el, f } = await center("audit", { "POST /api/audit/rule": () => ({ rule: "lamp.set:room=office" }) });
    await click(allByText(el, /^lamp\.set/, ".lrow")[0]);
    await click(button(el, "Allow with this value"));
    expect(f.to("POST", "/api/audit/rule")[0].body).toMatchObject({ node_id: "n-dev", list: "allow", cap: "lamp", action: "set", pin: { field: "room", value: "office" } });
  });

  it("offers no allow for a sudo command and says where its owner adds it", async () => {
    const d = centerData();
    d.overview.nodes[1].settings_write = true;
    const { el } = await center("audit", { "GET /api/overview": () => d.overview });
    await click(allByText(el, /sudo systemctl/, ".lrow")[0]);
    const detail = el.querySelector(".dcol")!;
    expect(allByText(detail, "Allow", "button")).toHaveLength(0);
    expect(allByText(detail, "Deny", "button")).toHaveLength(1);
    // office-pc runs Windows: the Nerve app's place, not a command.
    expect(text(detail)).toContain("in the Nerve app on that machine, Permissions, Sudo");
  });

  it("gives the exact sudo rule to paste, and none where no shell reads it the same", () => {
    expect(sudoRuleLine("sudo apt update *")).toBe("nerve-node rule add allow --action exec.run --exact 'sudo apt update *'");
    for (const odd of ["sudo echo 'x'", "sudo a\\b", "sudo a\nrm -rf /"]) expect(sudoRuleLine(odd)).toBeNull();
  });

  it("disables the machine's rules without its settings grant and says why", async () => {
    const { el } = await center("audit");
    await click(allByText(el, /sudo systemctl/, ".lrow")[0]);
    const deny = button(el.querySelector(".dcol")!, "Deny");
    expect(deny.disabled).toBe(true);
    expect(text(el)).toContain("This machine did not give this center the settings grant.");
  });

  it("lets a refusal of the model become a rule that skips it, and sends a blocklist refusal to the checker", async () => {
    const { el, f } = await center("audit", { "POST /api/checker/allow": () => ({ rule: "exec.run:rm -rf build/" }) });
    await click(allByText(el, /rm -rf build/, ".lrow")[0]);
    expect(text(el)).toContain("Decision model (on for every machine): deletes a tree");
    await click(button(el, "Trust this"));
    expect(f.to("POST", "/api/checker/allow")[0].body).toMatchObject({ cap: "exec", action: "run", target: "rm -rf build/", wildcard: false, node_id: "n-dev" });
    await click(allByText(el, /curl/, ".lrow")[0]);
    expect(button(el, "Switch this entry off for this machine").getAttribute("href")).toBe("#checker");
  });
});

describe("Action checker", () => {
  it("saves one change at a time, and a refused one leaves nothing behind", async () => {
    let release!: () => void;
    let saved = 0;
    const d = centerData();
    const { el, f } = await center("checker", {
      "GET /api/checker": () => d.checker,
      "POST /api/checker": () =>
        new Promise((_, no) => {
          saved++;
          release = () => no(refuse(409, "the settings changed since the page read them"));
        }),
    });
    const taint = el.querySelectorAll<HTMLButtonElement>(".strip [role=switch]")[2];
    expect(taint.getAttribute("aria-checked")).toBe("false");
    await click(taint);
    // While it saves, every control of the page is off.
    expect((el.querySelector("fieldset") as HTMLFieldSetElement).disabled).toBe(true);
    const reads = f.to("GET", "/api/checker").length;
    await act(async () => release());
    await settle(6);
    // A refusal reads the settings again: a newer version, saved meanwhile
    // from another page, is what the next change goes on.
    expect(f.to("GET", "/api/checker").length).toBeGreaterThan(reads);
    expect(saved).toBe(1);
    expect(f.to("POST", "/api/checker")[0].body).toMatchObject({ config: { taint_on: true, version: 7 } });
    // The center kept the old settings, and the page shows them.
    expect((el.querySelector("fieldset") as HTMLFieldSetElement).disabled).toBe(false);
    expect(el.querySelectorAll(".strip [role=switch]")[2].getAttribute("aria-checked")).toBe("false");
    expect(text(document.body)).toContain("the settings changed since the page read them");
  });

  it("adds a blocklist rule in the details pane, for one machine", async () => {
    const { el, f } = await center("checker", { "POST /api/checker": () => ({}) });
    await click(button(el, "Add a rule…"));
    await type(el.querySelector("input[aria-label='New blocklist rule']"), "lamp.set:room=hall");
    expect(text(el)).toContain("lamp.set takes level (an integer), room (a string).");
    await click(button(el, "One machine"));
    await click(el.querySelector(".dcol button[type=submit]"));
    const sent = f.to("POST", "/api/checker")[0].body as { config: { blocklist: { rule: string; node_id: string | null }[] } };
    expect(sent.config.blocklist.at(-1)).toMatchObject({ rule: "lamp.set:room=hall", node_id: "n-dev", on: true });
  });

  it("counts a machine's note in bytes, as the center does", async () => {
    const { el, f } = await center("checker", { "POST /api/checker": () => ({}) });
    await click(button(el, /^Per machine/));
    await type(el.querySelector("input[aria-label='Note on dev']"), "ä".repeat(150));
    expect(text(el)).toContain("100 bytes left");
    await type(el.querySelector("input[aria-label='Note on dev']"), "ä".repeat(201));
    expect(text(el)).toContain("2 bytes too long");
    await click(button(el, "Save note"));
    expect(f.to("POST", "/api/checker")).toHaveLength(0);
  });

  it("asks to install a model before it turns the model on without one", async () => {
    const d = centerData();
    d.checker.config.model_on = false;
    d.checker.installed = false;
    const { el, f } = await center("checker", { "GET /api/checker": () => d.checker, "POST /api/checker/install": () => ({}), "POST /api/checker": () => ({}) });
    await click(el.querySelectorAll(".strip [role=switch]")[1]);
    expect(text(document.querySelector("[role=dialog]")!)).toContain("Install d1-2B (1.9 GB) on the CPU now?");
    await click(button(document.querySelector("[role=dialog]")!, "Install and turn on"));
    await settle(6);
    expect(f.to("POST", "/api/checker/install")[0].body).toEqual({ gpu: false, model: "d1-2b" });
    expect(f.to("POST", "/api/checker")[0].body).toMatchObject({ config: { model_on: true } });
  });
});

describe("Capabilities", () => {
  it("checks the form of a new capability and shows what the machine refused", async () => {
    const { el, f } = await center("capabilities", {
      "POST /api/caps/check": (c) => ({ ok: false, errors: { name: (c.body.form as { name: string }).name.includes(".") ? "" : "a name is cap.action" } }),
      "POST /api/caps/save": () => {
        throw refuse(409, "the machine takes no capability named so");
      },
    });
    await click(button(el, "Add a capability…"));
    await type(el.querySelector(".dcol input[placeholder='backup.run']"), "backup");
    await act(async () => {
      await new Promise((r) => setTimeout(r, 400));
    });
    await settle();
    expect(text(el)).toContain("a name is cap.action");
    await click(el.querySelector(".dcol button[type=submit]"));
    expect(f.to("POST", "/api/caps/save")[0].body).toMatchObject({ id: "n-dev", adding: true });
    expect(text(el)).toContain("The machine refused: the machine takes no capability named so");
  });

  it("shows a machine without the settings grant read only, and says why one is not offered", async () => {
    const { el } = await center("capabilities");
    await click(allByText(el, /^lamp\.on/, ".lrow")[0]);
    expect(text(el)).toContain("only the machine's owner turns it on, with nerve-node cap set lamp.on on");
    await click(button(el, "office-pc"));
    expect(text(el)).toContain("Read only: this machine has not let this center change its settings.");
    expect(allByText(el, "Add a capability…", "button")).toHaveLength(0);
  });
});

describe("Help", () => {
  it("lists the node's commands and tells a Windows machine it has none", async () => {
    const { el } = await center("help");
    await click(button(el, /^nerve-node commands/));
    expect(text(el)).toContain("center add");
    expect(text(el)).toContain("A Windows machine has no nerve-node");
    await type(el.querySelector("input[aria-label='Filter the commands']"), "folder");
    expect(text(el.querySelector(".dcol")!)).not.toContain("Show the paired centers");
  });
});

describe("every page", () => {
  it("says its subtitles and notes in one short line", async () => {
    for (const p of ["overview", "nodes", "harnesses", "checker", "capabilities", "stats", "audit", "log", "settings", "help"]) {
      const { el } = await center(p);
      expect(el.querySelector("#top-title"), p).not.toBeNull();
      for (const s of el.querySelectorAll(".phead .sub, .sechead p, .lnote, .strip .note")) {
        expect(text(s).length, `${p}: ${text(s)}`).toBeLessThanOrEqual(120);
      }
    }
  });
});

// The Nerve node web UI. Plain JavaScript, no build step: the node serves
// this file as is, after the shared kit.js. Everything shown comes from
// /api, asked with this tab's session; every change is one command of the
// CLI that the node runs for its owner. The page asks the node every two
// seconds and draws again only when the answer changed.
"use strict";

const PAGES = {
  overview: { title: "Overview", view: pageOverview },
  centers: { title: "Centers", view: pageCenters },
  permissions: { title: "Permissions", view: pagePermissions },
  audit: { title: "Audit", view: pageAudit },
  log: { title: "Log", view: pageLog },
  capabilities: { title: "Capabilities", view: pageCaps },
  relay: { title: "Relay", view: pageRelay },
  settings: { title: "Settings", view: pageSettings },
  help: { title: "Help", view: pageHelp },
};

// The pages that ask their data once, when they open: each read is a
// command the node runs.
const LOADS = {
  permissions: () => loadPerm(),
  capabilities: () => loadCaps(),
  relay: async () => { state.relay = await api("GET", "/api/relay"); },
  settings: async () => { state.settings = await api("GET", "/api/settings"); },
  help: async () => { if (!state.help) state.help = await api("GET", "/api/help"); },
};

let lastSig = null;
let busy = false;
let down = false;
const state = { overview: null, ui: null, perm: null, permCenter: null, audit: null, log: null, preview: null, caps: null, relay: null, settings: null, help: null, shown: null, editing: null };
// The Audit and Log pages ask again every two seconds while Live is on.
const filters = { auditDenied: false, auditLive: true, logProblems: false, logLive: true };

// ---- Overview ----

function pageOverview() {
  const o = state.overview;
  if (!o) return [loading()];
  const up = o.centers.filter((c) => c.status === "connected").length;
  return [
    head("overview", "This machine", o.owner ? `Owner: ${o.owner}` : "No owner", [
      [`${up}/${o.centers.length}`, "centers connected", up ? "ok" : ""],
      [o.running, o.running === 1 ? "command running" : "commands running"],
    ], o.locked
      ? btn("Unlock", "primary", act(unlock), "ok", "unlock")
      : btn("Panic", "danger", act(panic), "ban", "panic")),
    o.locked ? banner("warn", "lock", "The node is locked: every link is closed and nothing runs until you unlock it.") : null,
    o.owner_is_root ? banner("warn", "alert", "Root is the owner: commands of user mode, and of allowlist mode as the owner, run as root and can do everything on this machine, Nerve and its keys included.") : null,
    o.pairings_warning ? banner("warn", "alert", o.pairings_warning) : null,
    section("Centers", "The centers this machine is paired with.", null,
      o.centers.length ? el("div", { class: "stack" }, o.centers.map(centerCard)) : empty("No center is paired yet.", "server")),
    section("Service", "Starting, stopping and restarting the node is done at the CLI.", null,
      el("p", { class: "meta" }, el("code", { class: "mono" }, "sudo systemctl restart nerve-node"))),
  ];
}

function centerCard(c) {
  const tone = c.revoked || c.unknown ? "warn" : c.status === "connected" ? "ok" : "neutral";
  return el("div", { class: "card" },
    el("div", { class: "card-top" },
      itile("server", tone),
      el("span", { class: "name" }, c.name),
      pill(c.status === "connected" ? "up" : "down", c.paused ? "paused" : c.status),
      el("span", { class: "meta push" }, c.mode)),
    el("p", { class: "meta" }, c.url),
    c.revoked ? el("p", { class: "meta" }, "The center revoked this machine.") : null,
    c.until ? el("p", { class: "meta" }, `Until ${when(c.until)}`) : null);
}

async function panic() {
  const yes = await modal({ title: "Panic?", message: "Every link closes and nothing runs until you unlock. Every web UI session ends too: you sign in again to unlock.", confirm: "Panic", danger: true });
  if (!yes) return;
  await api("POST", "/api/panic");
  // The panic ended this session as well.
  keepSession(null);
  location.assign("/login");
}

async function unlock() {
  await api("POST", "/api/unlock");
  notify("The node works again.");
}

// ---- Centers ----

function pageCenters() {
  const o = state.overview;
  if (!o) return [loading()];
  return [
    head("server", "Centers", "Pair this machine with a center, and decide what each one may change."),
    o.pairings_warning ? banner("warn", "alert", o.pairings_warning) : null,
    section("Pair a center", "Paste the link the center's web UI shows under Pair a machine. It goes to the node as the command's input, never in a command line.", null,
      pairForm()),
    section("Paired centers", null, null,
      o.centers.length ? el("div", { class: "stack" }, o.centers.map(centerManageCard)) : empty("No center is paired yet.", "server")),
  ];
}

function pairForm() {
  const link = el("input", { class: "input", type: "text", placeholder: "nerve://pair?…", autocomplete: "off", spellcheck: "false", "aria-label": "Pairing link" });
  const name = el("input", { class: "input", type: "text", placeholder: "Name here (optional)", autocomplete: "off", spellcheck: "false", "aria-label": "Name for the center here" });
  const p = state.preview;
  return el("div", { class: "card" },
    el("label", { class: "field" }, el("span", { class: "label" }, "Pairing link"), link),
    el("label", { class: "field" }, el("span", { class: "label" }, "Name"), name),
    p ? el("div", { class: "banner " + (p.check && p.check.ready ? "ok" : "warn") }, icon("info"),
      el("span", {}, `${p.preview.center}${p.preview.tls ? "" : " (plain HTTP on loopback)"}: ${p.check ? p.check.said || "" : ""}`)) : null,
    el("div", { class: "actions" },
      btn("Check", "ghost", act(async () => {
        state.preview = await api("POST", "/api/centers/preview", { link: link.value });
        draw(true);
      }), "check", "pair:check"),
      btn("Pair", "primary", act(async () => {
        const r = await api("POST", "/api/centers/pair", { link: link.value, name: name.value });
        state.preview = null;
        notify(`Paired with ${r.url || "the center"} as ${r.name || name.value}.`);
      }), "link", "pair:go")));
}

function centerManageCard(c) {
  const grant = c.settings === "write";
  return el("div", { class: "card" },
    el("div", { class: "card-top" }, itile("server", c.status === "connected" ? "ok" : "neutral"),
      el("span", { class: "name" }, c.name), pill(c.status === "connected" ? "up" : "down", c.paused ? "paused" : c.status)),
    el("p", { class: "meta" }, c.url),
    el("p", { class: "meta" }, grant ? "It may change its own rights here (the settings grant)." : "It may not change its own rights here."),
    el("div", { class: "actions" },
      btn(c.paused ? "Resume" : "Pause", "ghost", act(() => api("POST", c.paused ? "/api/centers/resume" : "/api/centers/pause", { center: c.name })), c.paused ? "ok" : "wait", `center:${c.name}:pause`),
      btn(grant ? "Take the grant away" : "Grant settings", "ghost", act(async () => {
        if (!grant) {
          const yes = await modal({ title: `Let ${c.name} change its rights?`, message: "It may then set everything this machine lets it do, up to user mode and sudo.", confirm: "Grant", danger: true });
          if (!yes) return;
        }
        await api("POST", "/api/centers/settings", { center: c.name, state: grant ? "off" : "on" });
      }), "key", `center:${c.name}:grant`),
      btn("New key", "ghost", act(async () => {
        await api("POST", "/api/centers/rotate", { center: c.name });
        notify("This machine has a new key for the center.");
      }), "refresh", `center:${c.name}:rotate`),
      btn("Remove", "danger-soft", act(async () => {
        const yes = await modal({ title: `Remove ${c.name}?`, message: "The node forgets the center and deletes its key. It has to be paired again to come back.", confirm: "Remove", danger: true });
        if (yes) await api("POST", "/api/centers/remove", { center: c.name });
      }), "trash", `center:${c.name}:remove`)));
}

// ---- Permissions ----

const MODES = [
  { value: "allowlist", text: "Allowlist: only what the allow rules name" },
  { value: "folder", text: "Folder: what each folder allows, as nerve-run" },
  { value: "user", text: "User: all you can do, as you" },
];

function permCenter() {
  const o = state.overview;
  if (!o || !o.centers.length) return null;
  if (!o.centers.some((c) => c.name === state.permCenter)) state.permCenter = o.centers[0].name;
  return state.permCenter;
}

async function loadPerm() {
  const c = permCenter();
  if (!c) return;
  state.perm = await api("GET", `/api/perm?center=${encodeURIComponent(c)}`);
  state.perm.center = c;
}

function pagePermissions() {
  const o = state.overview;
  if (!o) return [loading()];
  const c = permCenter();
  if (!c) return [head("shield", "Permissions"), empty("Pair a center first.", "server")];
  const entry = o.centers.find((x) => x.name === c);
  const p = state.perm && state.perm.center === c ? state.perm : null;
  return [
    head("shield", "Permissions", "How much each center may do on this machine."),
    o.centers.length > 1 ? segmented("Center", o.centers.map((x) => x.name), o.centers.findIndex((x) => x.name === c), (i) => {
      state.permCenter = o.centers[i].name; state.perm = null; draw(true); loadPerm().then(() => draw(true)).catch((e) => notify(e.message, "error"));
    }) : null,
    section("Mode", entry.until ? `Until ${when(entry.until)}` : null, null, modeForm(c, entry)),
    section("Network", "Whether its commands may open network sockets, in every mode.", null, networkForm(c, entry, o)),
    p ? foldersSection(c, p.folders.folders || []) : loading(),
    p ? rulesSection(c, p.rules) : null,
    p ? section("Sudo", "Turning sudo on is done at the CLI: sudo nerve-node sudo on.", null,
      el("div", { class: "card" }, el("div", { class: "card-top" }, icon("key"), el("span", { class: "name" }, `Sudo is ${p.sudo.sudo || "off"}`),
        p.sudo.sudo === "on" ? btn("Turn off", "danger-soft", act(() => api("POST", "/api/sudo/off")), "ban", "sudo:off") : null))) : null,
  ];
}

function modeForm(c, entry) {
  let chosen = entry.mode;
  const pick = segmented("Mode", MODES.map((m) => m.text), Math.max(0, MODES.findIndex((m) => m.value === entry.mode)), (i) => { chosen = MODES[i].value; });
  const hours = el("input", { class: "input", type: "number", min: "1", placeholder: "Hours (optional)", "aria-label": "For hours" });
  const owner = el("input", { type: "checkbox", checked: !!entry.as_owner });
  return el("div", { class: "card" },
    pick, hours,
    el("label", { class: "check" }, owner, el("span", {}, "In allowlist mode, run as you (the owner)")),
    el("div", { class: "actions" }, btn("Set the mode", "primary", act(() => api("POST", "/api/mode", {
      center: c, mode: chosen, hours: Number(hours.value) || undefined, as_owner: owner.checked,
    })), "check", `mode:${c}:set`)));
}

function networkForm(c, entry, o) {
  const off = el("input", { type: "checkbox", checked: !!entry.no_network });
  return el("div", { class: "card" },
    el("label", { class: "check" }, off, el("span", {}, "No network for its commands")),
    entry.no_network && o.network_rules === false
      ? el("p", { class: "meta" }, "This machine cannot keep commands off the network (the node's seccomp filter cannot be used here), so the node runs none of this center's commands while this is on.")
      : null,
    // The node says the commands run as the owner now (`network_off`),
    // which nothing keeps off the network.
    entry.network_off === "as_owner"
      ? el("p", { class: "meta" }, o.installed
        ? "In this mode its commands run as you, which nothing keeps off the network, so the node runs none of them while this is on. Folder mode, or allowlist mode as nerve-run, runs them."
        : "This node runs by hand, so its commands run as you, and nothing keeps them off the network here (only folder mode does, as a user that is not root and on Linux 7.1 or later), so the node runs none of them while this is on. The installed node runs folder mode's commands as nerve-run.")
      : null,
    entry.no_network ? el("p", { class: "meta" }, "No command on the sudo list runs while this is on.") : null,
    el("div", { class: "actions" }, btn("Save", "primary", act(() => api("POST", "/api/network", { center: c, off: off.checked })), "check", `network:${c}:set`)));
}

function foldersSection(c, folders) {
  const path = el("input", { class: "input", type: "text", placeholder: "/home/you/project", autocomplete: "off", spellcheck: "false", "aria-label": "Folder" });
  const box = (label) => { const b = el("input", { type: "checkbox", checked: label === "read" }); return [b, el("label", { class: "check" }, b, el("span", {}, label))]; };
  const [r, rl] = box("read"), [w, wl] = box("write"), [x, xl] = box("execute");
  return section("Folders", "What the center may do in each folder in folder mode. A whole path, starting at /.", null,
    folders.length ? el("div", { class: "stack" }, folders.map((f) => el("div", { class: "card" },
      el("div", { class: "card-top" }, icon("server"), el("span", { class: "name mono" }, f.path), el("span", { class: "meta push" }, f.rights),
        btn("Remove", "danger-soft", act(() => api("POST", "/api/folders/remove", { center: c, path: f.path }).then(loadPerm)), "trash", `folder:${f.path}:remove`))))) : empty("No folder yet.", "info"),
    el("div", { class: "card" }, path, el("div", { class: "actions" }, rl, wl, xl,
      btn("Add", "primary", act(() => api("POST", "/api/folders/add", { center: c, path: path.value, read: r.checked, write: w.checked, execute: x.checked }).then(loadPerm)), "plus", "folder:add"))));
}

function rulesSection(c, rules) {
  const lists = [["allow", "Allowed"], ["deny", "Forbidden"], ["sudo", "Run with sudo"]];
  return section("Rules", "Commands and patterns a center may run, may not, or runs with sudo. The guard's rules, which keep the commands off Nerve itself, are built in.", null,
    lists.map(([list, title]) => {
      const field = el("input", { class: "input", type: "text", placeholder: list === "sudo" ? "apt update" : "git status, git *, or fs.read:~/notes/*", autocomplete: "off", spellcheck: "false", "aria-label": `${title}: a new rule` });
      const wild = el("input", { type: "checkbox" });
      return el("div", { class: "card" },
        el("h4", {}, title),
        (rules[list] || []).length
          ? (rules[list] || []).map((rule) => el("div", { class: "card-top" }, el("code", { class: "mono" }, rule),
            rules.stale && rules.stale[rule] ? pill("warn", rules.stale[rule]) : null,
            btn("Remove", "danger-soft push", act(() => api("POST", "/api/rules/remove", { center: c, list, rule }).then(loadPerm)), "trash", `rule:${list}:${rule}:remove`)))
          : el("p", { class: "meta" }, "None."),
        el("div", { class: "actions" }, field, el("label", { class: "check" }, wild, el("span", {}, "Wildcard")),
          btn("Add", "primary", act(() => api("POST", "/api/rules/add", { center: c, list, rule: field.value, wildcard: wild.checked }).then(loadPerm)), "plus", `rule:${list}:add`)));
    }));
}

// ---- Audit ----

function pageAudit() {
  const a = state.audit;
  return [
    head("audit", "Audit", "What the node allowed and refused."),
    el("div", { class: "actions" },
      el("label", { class: "check" }, el("input", { type: "checkbox", checked: filters.auditDenied, onchange: (ev) => { filters.auditDenied = ev.target.checked; state.audit = null; tick(); } }), el("span", {}, "Refused only")),
      el("label", { class: "check" }, el("input", { type: "checkbox", checked: filters.auditLive, onchange: (ev) => { filters.auditLive = ev.target.checked; } }), el("span", {}, "Live")),
      btn("Clear", "danger-soft", act(async () => {
        const yes = await modal({ title: "Clear the audit?", message: "The entries so far are kept in the audit's older file.", confirm: "Clear", danger: true });
        if (yes) await api("POST", "/api/audit/clear");
      }), "trash", "audit:clear")),
    !a ? loading() : a.entries.length ? el("div", { class: "list" }, a.entries.slice().reverse().map(auditRow)) : empty("Nothing yet.", "audit"),
  ];
}

function auditRow(e) {
  const refused = e.decision === "forbidden" || e.event === "refused";
  const what = [e.cap, e.action].filter(Boolean).join(".");
  // What a button stores and where, as the node makes it (not as it is shown above).
  const add = (kind) => act(async () => {
    const r = e.rules[kind];
    const lists = { allow: "allow", deny: "deny", sudo: "sudo allow" };
    const yes = await modal({ title: `Add to the ${lists[r.list]} list?`, message: `For ${e.center}, as it will be stored: ${r.rule}`, confirm: "Add" });
    if (yes) await api("POST", "/api/audit/rule", { center: e.center, cap: e.cap, action: e.action, target: e.target, list: kind === "deny" ? "deny" : "allow", wildcard: kind === "wildcard" });
  });
  const button = (kind, label, cls, icon) => e.rules && e.rules[kind] && e.rules[kind].rule
    ? btn(label, cls, add(kind), icon, `audit:${e.ts}:${e.seq}:${kind}`) : null;
  return el("div", { class: "card" },
    el("div", { class: "card-top" }, itile(refused ? "ban" : "ok", refused ? "warn" : "ok"),
      el("span", { class: "name" }, what || e.event || "entry"), e.center ? pill("", e.center) : null,
      el("span", { class: "meta push", title: e.ts ? when(e.ts) : "" }, e.ts ? ago(e.ts) : "")),
    e.target ? el("p", { class: "mono" }, e.rule_preview || e.target) : null,
    e.reason ? el("p", { class: "meta" }, e.reason) : null,
    e.rule_preview && e.center ? el("div", { class: "actions" },
      button("allow", "Allow", "ghost", "ok"),
      button("wildcard", "Allow as wildcard", "ghost", "ok"),
      button("deny", "Deny", "danger-soft", "ban")) : null);
}

// ---- Log ----

function pageLog() {
  const l = state.log;
  return [
    head("log", "Log", "The node's starts and stops, its links, and what went wrong."),
    el("div", { class: "actions" },
      el("label", { class: "check" }, el("input", { type: "checkbox", checked: filters.logProblems, onchange: (ev) => { filters.logProblems = ev.target.checked; state.log = null; tick(); } }), el("span", {}, "Problems only")),
      el("label", { class: "check" }, el("input", { type: "checkbox", checked: filters.logLive, onchange: (ev) => { filters.logLive = ev.target.checked; } }), el("span", {}, "Live")),
      btn("Clear", "danger-soft", act(async () => {
        const yes = await modal({ title: "Clear the log?", message: "Its lines so far are deleted; one line says who cleared it.", confirm: "Clear", danger: true });
        if (yes) await api("POST", "/api/log/clear");
      }), "trash", "log:clear")),
    !l ? loading() : l.entries.length ? el("div", { class: "list" }, l.entries.slice().reverse().map((e) => el("div", { class: "card" },
      el("div", { class: "card-top" }, pill(e.level === "error" ? "down" : e.level === "warn" ? "warn" : "", e.level || ""),
        el("span", { class: "meta push", title: e.ts ? when(e.ts) : "" }, e.ts ? ago(e.ts) : "")),
      el("p", {}, e.msg || "")))) : empty("Nothing yet.", "log"),
  ];
}

// ---- Capabilities ----

async function loadCaps() {
  const c = permCenter();
  state.caps = await api("GET", `/api/caps${c ? `?center=${encodeURIComponent(c)}` : ""}`);
}

function pageCaps() {
  const v = state.caps;
  if (!v) return [loading()];
  const c = v.center;
  const known = Object.keys(v.known || {});
  return [
    head("plug", "Capabilities", c ? `What ${c} may use on this machine.` : "What the centers may use on this machine."),
    c ? section("Switches", "On, off, or hidden from the center. Unset, the mode decides.", null,
      known.length ? el("div", { class: "stack" }, known.map((cap) => {
        const now = (v.caps || {})[cap] || "by mode";
        return el("div", { class: "card" }, el("div", { class: "card-top" }, icon("plug"), el("span", { class: "name mono" }, cap), pill("", now),
          el("span", { class: "push" }, ["on", "off", "hidden"].map((w) => btn(w, w === now ? "primary" : "ghost",
            act(() => api("POST", "/api/caps/set", { center: c, cap, setting: w }).then(loadCaps)), null, `cap:${cap}:${w}`)))));
      })) : empty("Nothing to switch.", "plug")) : null,
    section("Your capabilities", "Actions of your own, each one fixed command, declared in node.toml.", null,
      (v.config || []).length ? el("div", { class: "stack" }, v.config.map((d) => el("div", { class: "card" },
        el("div", { class: "card-top" }, icon("terminal"), el("span", { class: "name mono" }, d.name), el("span", { class: "meta" }, d.summary || ""),
          el("span", { class: "push" },
            btn("Edit", "ghost", () => { state.editing = d.name; draw(true); }, "edit", `own:${d.name}:edit`),
            btn("Remove", "danger-soft", act(async () => {
              const yes = await modal({ title: `Remove ${d.name}?`, confirm: "Remove", danger: true });
              if (yes) await api("POST", "/api/caps/remove", { name: d.name }).then(loadCaps);
            }), "trash", `own:${d.name}:remove`)))))) : empty("None yet.", "terminal"),
      capForm((v.config || []).find((d) => d.name === state.editing))),
    section("Programs", "Local programs that may add capabilities to the node.", null,
      (v.programs || []).length ? el("div", { class: "stack" }, v.programs.map((p) => el("div", { class: "card" },
        el("div", { class: "card-top" }, icon("bot"), el("span", { class: "name" }, p.name), el("span", { class: "meta mono" }, p.exe || ""),
          btn("Remove", "danger-soft push", act(() => api("POST", "/api/programs/remove", { name: p.name }).then(loadCaps)), "trash", `program:${p.name}:remove`))))) : empty("None allowed.", "bot"),
      programForm()),
  ];
}

function field(label, attrs) {
  const input = el("input", Object.assign({ class: "input", type: "text", autocomplete: "off", spellcheck: "false" }, attrs));
  return [input, el("label", { class: "field" }, el("span", { class: "label" }, label), input)];
}

function area(label, attrs) {
  const input = el("textarea", Object.assign({ class: "json", rows: "4", spellcheck: "false" }, attrs));
  return [input, el("label", { class: "field" }, el("span", { class: "label" }, label), input)];
}

// One form to add a capability of your own or, with `entry`, to edit it.
// The node checks it again, and says which field is wrong.
function capForm(entry) {
  const f = entry ? entry.form : { name: "", summary: "", command: "", effect: "read", params: "", result: "", timeout: "", platform: "any" };
  const [name, nameF] = field("Name", { placeholder: "backup.run", value: f.name, disabled: !!entry });
  const [summary, summaryF] = field("What it does", { placeholder: "Backs up my notes.", value: f.summary });
  const [command, commandF] = field("Command", { placeholder: "restic backup /home/you/notes", value: f.command });
  const [params, paramsF] = area("Arguments (JSON schema, optional)", { value: f.params });
  const [result, resultF] = area("Result (JSON schema, optional; empty is plain text)", { value: f.result });
  const [timeout, timeoutF] = field("Timeout in seconds (empty: the node's default)", { value: f.timeout });
  let effect = f.effect;
  const effects = ["read", "write", "execute", "sense", "actuate"];
  let platform = f.platform;
  const platforms = ["any", "linux", "windows"];
  return el("div", { class: "card" }, nameF, summaryF, commandF,
    segmented("Effect", effects, Math.max(0, effects.indexOf(effect)), (i) => { effect = effects[i]; }),
    paramsF, resultF, timeoutF,
    segmented("Runs on", platforms, Math.max(0, platforms.indexOf(platform)), (i) => { platform = platforms[i]; }),
    el("div", { class: "actions" }, btn(entry ? "Save" : "Add", "primary", act(async () => {
      await api("POST", "/api/caps/save", { adding: !entry, form: { name: name.value, summary: summary.value, command: command.value, effect, params: params.value, result: result.value, timeout: timeout.value, platform } });
      state.editing = null;
      await loadCaps();
    }), entry ? "check" : "plus", entry ? `own:${f.name}:save` : "own:add"),
    entry ? btn("Cancel", "ghost", () => { state.editing = null; draw(true); }, "x", `own:${f.name}:cancel`) : null));
}

function programForm() {
  const [name, nameF] = field("Name", { placeholder: "lights" });
  const [exe, exeF] = field("Program", { placeholder: "/usr/local/bin/lights-provider" });
  return el("div", { class: "card" }, nameF, exeF,
    el("div", { class: "actions" }, btn("Allow", "primary", act(() => api("POST", "/api/programs/allow", { name: name.value, exe: exe.value }).then(loadCaps)), "plus", "program:allow")));
}

// ---- Relay ----

function pageRelay() {
  const v = state.relay;
  if (!v) return [loading()];
  const r = v.relay;
  const p = v.proxy;
  const [address, addressF] = field("Listen on", { placeholder: "0.0.0.0:7490", value: r.listen || "" });
  const [node, nodeF] = field("Node", { placeholder: "lab-pc" });
  const [url, urlF] = field("Relay or proxy", { placeholder: "https://lab-pc@relay.example:7490" });
  const [pw, pwF] = field("Its token or password", { type: "password" });
  const reload = async () => { state.relay = await api("GET", "/api/relay"); };
  const shown = state.shown;
  return [
    head("link", "Relay", "Reach centers through another node, or let other nodes reach this node's centers through this one."),
    section("Connect through a relay", p.proxy ? `Now through ${p.proxy}.` : "This node reaches its centers directly.", null,
      el("div", { class: "card" }, urlF, pwF, el("div", { class: "actions" },
        btn("Connect", "primary", act(() => api("POST", "/api/proxy/set", { url: url.value, password: pw.value }).then(reload)), "link", "proxy:set"),
        p.proxy ? btn("Disconnect", "danger-soft", act(() => api("POST", "/api/proxy/remove").then(reload)), "x", "proxy:rm") : null))),
    section("This machine as a relay", r.listen ? `On ${r.listen}: ${r.status || ""}` : "Off.", null,
      el("div", { class: "card" }, addressF, el("div", { class: "actions" },
        btn(r.listen ? "Change" : "Turn on", "primary", act(() => api("POST", "/api/relay/set", { address: address.value }).then(reload)), "check", "relay:set"),
        r.listen ? btn("Turn off", "danger-soft", act(() => api("POST", "/api/relay/off").then(reload)), "x", "relay:off") : null)),
      shown ? el("div", { class: "banner ok" }, icon("key"), el("span", {}, `The link for ${shown.node}, shown once: `, el("code", { class: "mono" }, shown.link)),
        el("button", { type: "button", class: "btn ghost sm", onclick: () => copy(shown.link) }, icon("copy", "sm"), "Copy"),
        el("button", { type: "button", class: "btn ghost sm", "aria-label": "Hide", onclick: () => { state.shown = null; draw(true); } }, icon("x", "sm"))) : null,
      (r.nodes || []).map((n) => el("div", { class: "card" }, el("div", { class: "card-top" }, icon("server"), el("span", { class: "name" }, n.name),
        el("span", { class: "meta" }, n.centers && n.centers.length ? n.centers.join(", ") : "every https center"),
        el("span", { class: "push" },
          btn("New link", "ghost", act(async () => { const t = await api("POST", "/api/relay/token", { name: n.name }); state.shown = t.token; await reload(); }), "refresh", `relay:${n.name}:token`),
          btn("Remove", "danger-soft", act(() => api("POST", "/api/relay/remove", { name: n.name }).then(reload)), "trash", `relay:${n.name}:remove`))))),
      el("div", { class: "card" }, nodeF, el("div", { class: "actions" },
        btn("Add a node", "primary", act(async () => { const t = await api("POST", "/api/relay/add", { name: node.value }); state.shown = t.token; await reload(); }), "plus", "relay:add")))),
  ];
}

// ---- Help ----

let helpParts = null;

function pageHelp() {
  const h = state.help && state.help.node;
  if (!h) return [loading()];
  if (!helpParts) helpParts = buildHelp(h);
  return helpParts;
}

// ---- Settings ----

const LEVELS = ["error", "warn", "info", "debug"];

function pageSettings() {
  const s = state.ui;
  const v = state.settings;
  if (!s || !v) return [loading()];
  const [name, nameF] = field("Name of this machine", { value: v.name || "" });
  let level = v.log_level;
  const [key, keyF] = field("Setting", { placeholder: "limits.max_running" });
  const [value, valueF] = field("Value, as TOML", { placeholder: "4" });
  const set = (k, val) => api("POST", "/api/settings/set", { key: k, value: val }).then(async () => { state.settings = await api("GET", "/api/settings"); });
  return [
    head("settings", "Settings", "The node's settings."),
    section("This machine", null, null, el("div", { class: "card" }, nameF,
      el("div", { class: "actions" }, btn("Save", "primary", act(() => set("node.name", JSON.stringify(name.value))), "check", "settings:name")),
      segmented("Log level", LEVELS, Math.max(0, LEVELS.indexOf(level)), (i) => { level = LEVELS[i]; }),
      el("div", { class: "actions" }, btn("Set the log level", "ghost", act(() => set("log.level", JSON.stringify(level))), "check", "settings:level")),
      el("p", { class: "meta" }, `Keys are kept in ${v.secret_storage === "keyring" ? "the system keyring" : "files"}.`))),
    section("Root's settings", "Which account and which programs commands run as. They are shown here and changed only as root: sudo nerve-node config set …", null,
      el("div", { class: "card" }, v.root_only.map((k) => {
        const leaf = k.split(".")[1];
        const val = v.machine[leaf];
        return el("p", { class: "meta" }, el("code", { class: "mono" }, k), ` ${val === undefined || val === null ? "not set" : String(val)}`);
      }))),
    section("Advanced", "Any setting by its name, as nerve-node config set takes it. Backup, restore, update and uninstall are done at the CLI.", null,
      el("div", { class: "card" }, keyF, valueF, el("div", { class: "actions" },
        btn("Set", "primary", act(() => set(key.value, value.value)), "check", "settings:set"),
        btn("Unset", "ghost", act(() => api("POST", "/api/settings/unset", { key: key.value }).then(async () => { state.settings = await api("GET", "/api/settings"); })), "x", "settings:unset")),
        el("pre", { class: "mono" }, v.toml))),
    section("Web UI", "Turning it on or off, its address and new tokens are changed at the CLI: nerve-node ui.", null,
      el("div", { class: "card" },
        el("div", { class: "card-top" }, itile("monitor", "accent"), el("span", { class: "name" }, s.ui.listen || "off"), pill("up", s.ui.status)),
        el("p", { class: "meta" }, plural(s.ui.sessions, "session") + " signed in")),
      s.tokens.length
        ? el("div", { class: "stack" }, s.tokens.map(tokenCard))
        : empty("No token. nerve-node ui token add <label> makes one.", "key")),
  ];
}

function tokenCard(t) {
  return el("div", { class: "card" }, el("div", { class: "card-top" },
    icon("key"), el("span", { class: "name" }, t.label),
    el("span", { class: "meta push" }, t.made ? `Made ${t.made}` : ""),
    btn("Revoke", "danger-soft", act(async () => {
      const yes = await modal({ title: `Revoke ${t.label}?`, message: "It no longer logs in, and the sessions it opened end, this one too if it did. A new token is made at the CLI.", confirm: "Revoke", danger: true });
      if (yes) await api("POST", "/api/ui/revoke", { label: t.label });
    }), "trash", `token:${t.label}:revoke`)));
}

// ---- Drawing ----

function current() {
  const h = location.hash.slice(1);
  return PAGES[h] ? h : "overview";
}

function draw(force) {
  const page = current();
  const extra = { settings: [state.ui, state.settings], permissions: state.perm, audit: state.audit, log: state.log, centers: state.preview, capabilities: state.caps, relay: [state.relay, state.shown], help: !!state.help }[page];
  const sig = JSON.stringify([page, state.overview, extra === undefined ? null : extra, Math.floor(Date.now() / 60000)]);
  if (!force && sig === lastSig) return;
  lastSig = sig;
  replacePage(PAGES[page].view().flat().filter((p) => p != null));
}

async function tick() {
  if (busy || !session) return;
  busy = true;
  try {
    const page = current();
    const jobs = [api("GET", "/api/overview")];
    if (page === "settings") jobs.push(api("GET", "/api/ui"));
    // The audit and the log are read by the node itself, in place; nothing
    // runs for them.
    if (page === "audit" && (filters.auditLive || !state.audit)) jobs.push(api("GET", `/api/audit${filters.auditDenied ? "?denied=1" : ""}`));
    if (page === "log" && (filters.logLive || !state.log)) jobs.push(api("GET", `/api/log${filters.logProblems ? "?problems=1" : ""}`));
    const [o, extra] = await Promise.all(jobs);
    state.overview = o;
    if (page === "settings") state.ui = extra;
    if (page === "audit" && extra) state.audit = extra;
    if (page === "log" && extra) state.log = extra;
    if (down) notify("Connected to the node again.");
    down = false;
    draw(false);
  } catch (e) {
    if (!e.auth && !down) notify("Cannot reach the node. Trying again.", "error");
    down = !e.auth;
  } finally {
    busy = false;
  }
}

// ---- Shell: navigation, drawer ----

function setNav(open) {
  $("shell").dataset.nav = open ? "open" : "";
  $("nav-open").setAttribute("aria-expanded", String(open));
  if (open) $("nav-close").focus();
}

function go() {
  const page = current();
  for (const a of document.querySelectorAll("[data-page]")) {
    if (a.dataset.page === page) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  $("top-title").textContent = PAGES[page].title;
  setNav(false);
  lastSig = null;
  pendingFocus = null;
  const p = $("page");
  p.classList.remove("enter");
  void p.offsetWidth;
  p.classList.add("enter");
  $("scroll").scrollTop = 0;
  draw(true);
  if (LOADS[page]) tick().then(LOADS[page]).then(() => draw(true)).catch((e) => { if (!e.auth) notify(e.message, "error"); });
  else tick();
}

$("nav-open").addEventListener("click", () => setNav(true));
$("nav-close").addEventListener("click", () => { setNav(false); $("nav-open").focus(); });
$("scrim").addEventListener("click", () => setNav(false));
for (const a of document.querySelectorAll("[data-page]")) a.addEventListener("click", () => setNav(false));
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && $("shell").dataset.nav === "open") { setNav(false); $("nav-open").focus(); }
});
window.addEventListener("hashchange", go);
document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(); });
$("signout").addEventListener("submit", (ev) => { ev.preventDefault(); signOut(); });

async function start() {
  try {
    if (!(await startSession())) return;
  } catch (_) {
    return $("page").replaceChildren(banner("", "alert", "Cannot reach the node. Reload to try again."));
  }
  go();
  setInterval(() => { if (!document.hidden) tick(); }, 2000);
}

start();

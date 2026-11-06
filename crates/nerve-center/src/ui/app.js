// The Nerve center web UI. Plain JavaScript, no build step: the binary
// serves this file as is, after the shared kit.js. Everything shown comes
// from /api, asked with this tab's session. The page asks the center every
// two seconds and draws again only when the answer changed.
"use strict";

const PAGES = {
  overview: { title: "Overview", view: pageOverview },
  stats: { title: "Statistics", view: pageStats },
  audit: { title: "Audit", view: pageAudit },
  checker: { title: "Action checker", view: pageChecker },
  capabilities: { title: "Capabilities", view: pageCaps },
  log: { title: "Log", view: pageLog },
  help: { title: "Help", view: pageHelp },
  settings: { title: "Settings", view: pageSettings },
};

let lastSig = null;
let busy = false;
let down = false;
let settingsRun = 0;
const state = { overview: null, stats: null, statsNode: null, audit: null, log: null, help: null, pairing: null, settings: null, newToken: null, newPin: null, checker: null, caps: null, capsNode: null };

let helpParts = null;

function pageHelp() {
  const h = state.help && state.help.node;
  if (!h) return [loading()];
  if (!helpParts) helpParts = buildHelp(h);
  return helpParts;
}

// ---- Overview ----

function pageOverview() {
  const o = state.overview;
  if (!o) return [loading()];
  const online = o.nodes.filter((n) => n.online).length;
  return [
    head("overview", o.center.name, o.center.url, [
      [`${online}/${o.nodes.length}`, "machines online", online ? "ok" : ""],
      [o.sessions.length, o.sessions.length === 1 ? "session" : "sessions"],
    ]),
    o.alerts.slice(-5).map((a) => banner("warn", "alert", `${when(a.ts)}: ${a.text}`)),
    section("Machines", null, btn("Pair a machine", "primary", act(async () => { state.pairing = await api("POST", "/api/pair"); }), "plus", "pair"),
      state.pairing ? pairingCard(state.pairing) : null,
      o.nodes.length ? el("div", { class: "stack" }, o.nodes.map(nodeCard)) : empty("No machines yet. Pair one to get started.", "server")),
    section("Sessions", "Harnesses that are connected to this center.", null,
      o.sessions.length ? el("div", { class: "list" }, o.sessions.map(sessionCard)) : empty("No harness is connected.", "plug")),
  ];
}

function pairingCard(p) {
  const command = `nerve-node center add '${p.link}'`;
  // The two ways a machine takes it, each with its own copy button: the
  // command for a terminal, the bare link for the desktop app. The link
  // holds the center, the code and the pin, so they are not shown apart.
  const row = (label, value) => el("div", { class: "pair-row" },
    el("span", { class: "pair-label" }, label),
    el("code", { class: "pair-value mono" }, value),
    btn("Copy", "ghost", () => copy(value), "copy", `pair:copy:${label}`));
  return el("div", { class: "card", id: "pairing" },
    el("div", { class: "card-top" }, itile("link", "accent"), el("span", { class: "name" }, "Pair a machine"),
      el("button", { type: "button", class: "btn ghost icon sm push", "aria-label": "Dismiss", "data-focus": "pair:dismiss", onclick: () => { state.pairing = null; draw(true); } }, icon("x", "sm"))),
    el("p", { class: "meta" }, "On the machine, run the command, or paste the link in the Nerve app (Centers, Pair a center)."),
    el("div", { class: "pair-rows" },
      row("Command", command),
      row("Link", p.link)),
    el("p", { class: "meta" }, `The code is valid until ${when(p.expires_ms)} and works for one machine.`),
    p.pin ? null : el("p", { class: "meta faint" }, "Plain HTTP on loopback, no certificate pin."));
}

function nodeCard(n) {
  const caps = n.capabilities || [];
  // Actions the center left out: a bad name, or a schema it cannot check
  // arguments with. The owner learns why here; the agent never sees them.
  const broken = n.broken || [];
  return el("div", { class: "card" },
    el("div", { class: "card-top" },
      itile("server", n.disabled ? "warn" : n.online ? "ok" : "neutral"),
      el("span", { class: "name" }, n.name),
      pill(n.online ? "up" : "down", n.online ? n.status || "online" : "offline"),
      n.disabled ? pill("warn", "disabled") : null,
      el("span", { class: "meta push" }, `${n.platform}/${n.arch}`)),
    el("p", { class: "meta", title: when(n.online ? n.since_ms : n.last_seen_ms) },
      n.online ? `Since ${ago(n.since_ms)}` : `Last seen ${ago(n.last_seen_ms)}`),
    n.going_away ? el("p", { class: "meta" }, `Going away: ${n.going_away}`) : null,
    n.disabled ? el("p", { class: "meta" }, "Hidden from the agent: it is offered none of this machine's capabilities, and calls to it are refused.") : null,
    n.summary ? el("p", {}, n.summary) : null,
    caps.length
      ? el("div", { class: "chips" }, caps.map((c) => el("span", { class: "chip" + (c.exposure === "off" ? " off" : ""), title: `${c.summary || c.id} (${c.exposure})` }, c.id)))
      : el("p", { class: "meta" }, "Offers nothing yet."),
    broken.length
      ? el("div", { class: "broken" },
        el("p", { class: "meta" }, "Not offered to the agent:"),
        broken.map((b) => el("p", { class: "meta" }, el("code", { class: "mono" }, b.name), ` ${b.reason}`)))
      : null,
    el("div", { class: "actions" },
      btn("Rename", "ghost", act(async () => {
        const name = await modal({ title: `Rename ${n.name}`, confirm: "Rename", field: { label: "New name (a-z, 0-9 and -, not starting or ending with -)", value: n.name, pattern: "[a-z0-9]([a-z0-9\\-]*[a-z0-9])?" } });
        if (name && name !== n.name) await api("POST", "/api/nodes/rename", { id: n.id, name });
      }), "edit", `node:${n.id}:rename`),
      btn(n.disabled ? "Enable" : "Disable", "ghost", act(() => api("POST", "/api/nodes/disable", { id: n.id, disabled: !n.disabled })), n.disabled ? "ok" : "ban", `node:${n.id}:disable`),
      btn("Remove", "ghost", act(async () => {
        const yes = await modal({ title: `Remove ${n.name}?`, message: "It has to be paired again to come back.", confirm: "Remove", danger: true });
        if (yes) await api("POST", "/api/nodes/remove", { id: n.id });
      }), "trash", `node:${n.id}:remove`)));
}

function sessionCard(s) {
  return el("div", { class: "card" },
    el("div", { class: "card-top" }, itile("plug", "accent"), el("span", { class: "name" }, s.client || "Unknown client"),
      pill("", s.transport),
      // The action checker marks a session tainted once a call of it returned
      // content (issue #17).
      s.tainted ? pill("warn", "tainted") : null,
      el("span", { class: "push" }, btn("End", "danger-soft", act(() => api("POST", "/api/sessions/end", { id: s.id })), null, `session:${s.id}:end`))),
    el("p", { class: "meta" }, `Since ${ago(s.started_ms)}, ${plural(s.calls, "call")}`),
    s.nodes.length ? el("div", { class: "chips" }, s.nodes.map((n) => el("span", { class: "chip" }, n))) : null,
    el("p", { class: "meta faint mono" }, s.id));
}

// ---- Searchable list ----

let pickers = 0;

// A list to pick one entry from, with a search field, for when a <select>
// would be too long to read. A button shows the choice and opens a panel with
// the search field above a list of fixed height. The keys follow the combobox
// pattern: Down opens it, Up and Down move, Enter picks, Escape closes.
// `items` are { value, text }; `onpick` gets the value of the entry picked.
// `key` names the button for the focus (see focusSpot).
function picker(o) {
  const n = ++pickers;
  const ids = { label: `pick-${n}-label`, button: `pick-${n}-button`, list: `pick-${n}-list` };
  let items = [];
  let chosen = null;
  let shown = [];
  let active = -1;
  let open = false;

  const current = el("span", {});
  const button = el("button", {
    type: "button", class: "input picker-btn", id: ids.button, "data-focus": o.key, "aria-haspopup": "listbox", "aria-expanded": "false",
    "aria-controls": ids.list, "aria-labelledby": `${ids.label} ${ids.button}`,
  }, current, icon("chev", "sm chev"));
  const search = el("input", {
    class: "input", type: "text", role: "combobox", placeholder: "Search…", "aria-label": o.search, "aria-controls": ids.list,
    "aria-expanded": "true", "aria-autocomplete": "list", autocomplete: "off", spellcheck: "false",
  });
  // tabindex -1: a list that scrolls is a stop for Tab in some browsers, and the keys work on the search field.
  const list = el("ul", { class: "picker-list", id: ids.list, role: "listbox", tabindex: "-1", "aria-labelledby": ids.label });
  const none = el("p", { class: "picker-none", role: "status" });
  const panel = el("div", { class: "picker-panel", hidden: true }, search, list, none);
  const root = el("div", { class: "field picker" }, el("span", { class: "label", id: ids.label }, o.label), button, panel);

  // Marks the entry the keys act on; `reveal` scrolls the list to it.
  function mark(k, reveal) {
    active = k;
    for (const [j, li] of Array.from(list.children).entries()) li.classList.toggle("active", j === k);
    const li = list.children[k];
    if (!li) return search.removeAttribute("aria-activedescendant");
    search.setAttribute("aria-activedescendant", li.id);
    if (!reveal) return;
    if (li.offsetTop < list.scrollTop) list.scrollTop = li.offsetTop;
    else if (li.offsetTop + li.offsetHeight > list.scrollTop + list.clientHeight) list.scrollTop = li.offsetTop + li.offsetHeight - list.clientHeight;
  }

  // Lists the entries that contain the search text, and marks the one with
  // value `keep`, or else the first.
  function render(keep) {
    const q = search.value.trim().toLowerCase();
    shown = items.filter((i) => i.text.toLowerCase().includes(q));
    list.replaceChildren(...shown.map((i, k) => el("li", {
      id: `${ids.list}-${k}`, role: "option", class: "opt", title: i.text, "aria-selected": String(i.value === chosen),
      // A scroll under a still pointer sends a move of no distance: not a choice.
      onmousemove: (ev) => { if ((ev.movementX || ev.movementY) && k !== active) mark(k, false); },
      onclick: () => pick(i),
    }, el("span", {}, i.text), i.value === chosen ? icon("check", "sm") : null)));
    none.textContent = shown.length ? "" : o.none;
    mark(shown.length ? Math.max(0, shown.findIndex((i) => i.value === keep)) : -1, true);
  }

  function show(on, refocus) {
    if (on === open) return;
    open = on;
    panel.hidden = !on;
    button.setAttribute("aria-expanded", String(on));
    if (on) {
      search.value = "";
      render(chosen);
      search.focus();
    } else if (refocus) {
      button.focus();
    }
  }

  function pick(item) {
    show(false, true);
    if (item.value !== chosen) o.onpick(item.value);
  }

  button.addEventListener("click", () => show(!open, true));
  // Safari does not focus a button on click: keep the focus in the search
  // field, so the click closes the panel instead of reopening it.
  button.addEventListener("mousedown", (ev) => { if (open) ev.preventDefault(); });
  button.addEventListener("keydown", (ev) => {
    if (ev.key === "ArrowDown" || ev.key === "ArrowUp") { ev.preventDefault(); show(true, true); }
  });
  search.addEventListener("input", () => render(search.value.trim() ? undefined : chosen));
  search.addEventListener("keydown", (ev) => {
    const arrow = { ArrowDown: 1, ArrowUp: -1 }[ev.key];
    const page = { PageDown: 6, PageUp: -6 }[ev.key];
    if (arrow || page) {
      ev.preventDefault();
      const last = shown.length - 1;
      if (last >= 0) mark(arrow ? (active + arrow + shown.length) % shown.length : Math.min(last, Math.max(0, active + page)), true);
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      if (shown[active]) pick(shown[active]);
    } else if (ev.key === "Escape") {
      ev.preventDefault();
      ev.stopPropagation();
      show(false, true);
    }
  });
  // A click on the panel that is not on the search field must not take the
  // focus off it, or the panel would close before the click lands.
  panel.addEventListener("mousedown", (ev) => { if (ev.target !== search) ev.preventDefault(); });
  root.addEventListener("focusout", (ev) => { if (open && !root.contains(ev.relatedTarget)) show(false, false); });

  return {
    root,
    close: () => show(false, false),
    // New entries and the value now chosen, while the panel may be open.
    set(next, value) {
      // The same entries again (the poll): leave the list as it is, with its scroll.
      const same = value === chosen && next.length === items.length && next.every((i, k) => i.value === items[k].value);
      items = next;
      chosen = value;
      const at = items.find((i) => i.value === value);
      current.textContent = at ? at.text : "";
      if (open && !same) render(shown[active] ? shown[active].value : undefined);
    },
  };
}

// ---- Statistics ----

// The picker and the boxes around it are made once and kept: draw() leaves
// them in place when the numbers change, so a search typed into the picker
// is not cut off by the next poll.
const statsPicker = picker({
  label: "Machine", search: "Search machines", none: "No machine matches.",
  onpick: (name) => { state.statsNode = name; draw(true); },
});
const statsParts = { head: el("div"), pick: el("div", { class: "picker-row" }, statsPicker.root), body: el("div") };

// The numbers of all machines together, or of the one picked from the list.
function pageStats() {
  const s = state.stats;
  if (!s) return [loading()];
  const paired = state.overview ? state.overview.nodes.map((n) => n.name) : [];
  const names = [...new Set([...paired, ...Object.keys(s.nodes)])].sort((a, b) => a.localeCompare(b));
  // A machine that was removed or renamed has no numbers under that name.
  if (state.statsNode !== null && !names.includes(state.statsNode)) state.statsNode = null;
  const one = state.statsNode;
  const title = `Statistics: ${one === null ? "all machines" : one}`;
  $("top-title").textContent = title;
  statsPicker.set([{ value: null, text: "All machines" }, ...names.map((m) => ({ value: m, text: m }))], one);
  statsParts.head.replaceChildren(head("stats", title, `Kept for ${plural(s.retention_days, "day")}.`, [[names.length, names.length === 1 ? "machine" : "machines"]]));
  statsParts.pick.hidden = !names.length;
  statsParts.body.replaceChildren(names.length ? dayCard((one === null ? s.total : s.nodes[one]) || {}) : empty("No machines yet.", "server"));
  return [statsParts.head, statsParts.pick, statsParts.body];
}

function dayCard(d) {
  const calls = Object.entries(d.calls || {}).sort((a, b) => b[1].count - a[1].count);
  const errors = Object.entries(d.errors || {}).sort((a, b) => b[1] - a[1]);
  const total = calls.reduce((n, [, c]) => n + c.count, 0);
  const failed = calls.reduce((n, [, c]) => n + c.errors, 0);
  const metrics = [
    [duration(d.online_ms || 0), "Online"], [d.links || 0, "Links"], [d.drops || 0, "Drops"],
    [total, "Calls"], [failed, "Failed calls"],
  ];
  const rows = (title, list, line) => list.length ? [el("p", { class: "meta" }, title), el("div", { class: "rows" }, list.map(([k, v]) =>
    el("div", {}, el("span", { class: "mono" }, k), el("span", { class: "v" }, line(v))))) ] : null;
  return el("div", { class: "card" },
    el("div", { class: "metrics" }, metrics.map(([v, l]) => el("div", { class: "metric" }, el("b", {}, v.toLocaleString()), el("span", {}, l)))),
    rows("Calls", calls, (c) => `${c.count}${c.errors ? `, ${c.errors} failed` : ""}, avg ${c.count ? Math.round(c.total_ms / c.count) : 0} ms, max ${c.max_ms} ms`),
    rows("Errors", errors, (n) => n));
}

// ---- Audit ----

// The longest owner's note on a machine, in UTF-8 bytes, as the center
// takes it (checker::config::NOTE_MAX).
const NOTE_MAX = 400;

const DECISIONS = {
  allowed: { ic: "ok", tone: "ok", pill: "up" },
  denied: { ic: "ban", tone: "danger", pill: "down" },
  forbidden: { ic: "lock", tone: "danger", pill: "down" },
  // A command the node killed for its memory limit, after it was allowed.
  killed: { ic: "ban", tone: "danger", pill: "down" },
};

function pageAudit() {
  const a = state.audit;
  if (!a || !state.overview) return [loading()];
  const nodes = Object.fromEntries(state.overview.nodes.map((n) => [n.id, n]));
  const list = a.decisions.slice().reverse();
  const shown = list.slice(0, 200);
  return [
    head("audit", "Audit", "Every decision about a call, newest first.", [[list.length, list.length === 1 ? "decision" : "decisions"]]),
    shown.length ? el("div", { class: "list" }, shown.map((d) => auditRow(d, nodes[d.node_id])), list.length > shown.length
      ? el("p", { class: "meta" }, `Showing the latest ${shown.length} of ${list.length}.`) : null)
      : empty("No decisions yet.", "audit"),
  ];
}

function auditRow(d, n) {
  const k = DECISIONS[d.decision] || { ic: "info", tone: "", pill: "" };
  // A decision the center's action checker made (issue #17): its own allow
  // rules, no node grant needed.
  if (d.by === "action checker") return checkerAuditRow(d, k);
  const write = n && n.settings_write;
  const why = !n ? "The machine is no longer paired." : !write ? "This machine did not give this center the settings grant." : "";
  const rule = (list, wildcard, pin) => act(async () => {
    const r = await api("POST", "/api/audit/rule", { node_id: d.node_id, list, cap: d.cap, action: d.action, target: d.target || "", wildcard, pin: pin ? pin() : null });
    notify(`Added to the ${list === "sudo" ? "sudo allow" : list} list: ${r.rule}`);
  });
  // A decision has no id; its time, machine and call name it.
  const auditKey = `audit:${d.ts}:${d.node_id}:${d.cap}.${d.action}`;
  const ruleBtn = (label, kind, list, wildcard, ic, pin) => {
    const b = btn(label, kind, rule(list, wildcard, pin), ic, `${auditKey}:${label}`);
    if (!write) { b.disabled = true; b.title = why; }
    return b;
  };
  // The call's arguments a rule may pin: the rule then holds that one value.
  const pins = pinPicker(d, auditKey);
  // A rule needs the entry's target: a command line or a path. Any other
  // action is its own target. A target cut to its start names no call, which
  // only matters where the rule names the target (a command line or a path).
  const cut = (d.cap === "fs" || (d.cap === "exec" && d.action === "run")) && /… \[cut at \d+ of \d+ characters\]$/.test(d.target || "");
  const known = d.cap && d.action && !cut && (d.target || !["exec", "fs"].includes(d.cap));
  // A sudo command has its own allow list; deny rules take it as any other.
  const sudo = d.cap === "exec" && d.action === "run" && /^\s*(\S*\/)?sudo(\s|$)/.test(d.target || "");
  const allow = sudo ? "sudo" : "allow";
  return el("div", { class: "card audit-row" },
    itile(k.ic, k.tone || "neutral"),
    el("div", { class: "line" },
      el("b", {}, d.node), el("span", { class: "mono" }, `${d.cap}.${d.action}`),
      pill(k.pill, d.decision + (d.by ? ` by ${d.by}` : "") + (d.code ? ` [${d.code}]` : "")),
      el("span", { class: "when", title: when(d.ts) }, ago(d.ts))),
    d.target ? el("code", { class: "target mono" }, d.target) : null,
    known ? el("div", { class: "actions" },
      ruleBtn("Allow", "", allow, false, "check"), ruleBtn("Allow as wildcard", "", allow, true),
      ruleBtn("Deny", "danger-soft", "deny", false, "ban"), ruleBtn("Deny as wildcard", "danger-soft", "deny", true)) : null,
    known && pins ? el("div", { class: "actions pins" }, pins.root,
      ruleBtn("Allow with this value", "", "allow", false, null, pins.pin), ruleBtn("Deny with this value", "danger-soft", "deny", false, null, pins.pin)) : null,
    known && !write ? el("p", { class: "meta" }, why) : null,
    cut ? el("p", { class: "meta" }, "The target was cut to its start, so no rule can name it.") : null);
}

// A choice of the arguments of an audit entry's call that a rule may pin
// (`d.args`, kept by the machine), or null where there are none: its root and
// the pin chosen, as {field, value}, for /api/audit/rule and
// /api/checker/allow.
function pinPicker(d, auditKey) {
  const args = d.args && typeof d.args === "object" ? Object.entries(d.args) : [];
  if (!args.length) return null;
  const text = ([k, v]) => `${k}=${typeof v === "string" ? v.replace(/\\/g, "\\\\").replace(/,/g, "\\,") : String(v)}`;
  const items = args.map((a, i) => ({ value: String(i), text: text(a) }));
  let chosen = "0";
  const p = picker({ label: "Pin one argument", search: "Search arguments", none: "No argument matches.", key: `${auditKey}:pin`,
    onpick: (v) => { chosen = v; p.set(items, v); } });
  p.set(items, chosen);
  return {
    root: p.root,
    pin: () => { const [field, value] = args[Number(chosen) || 0]; return { field, value }; },
  };
}

// A row for a decision the action checker made. A refusal offers allow
// buttons that save a checker allow rule (center-side, no node grant), unless
// the blocklist did it: the blocklist is hard deny, so the owner removes or
// switches the entry off on the Action checker page instead.
function checkerAuditRow(d, k) {
  const layer = d.checker ? d.checker.layer : "";
  const detail = d.checker ? d.checker.detail : "";
  // Whether the entry, rule or switch behind it was the center's for every
  // machine or this machine's own (entries from before per-machine settings
  // have no scope).
  const scope = d.checker ? d.checker.scope : "";
  // For the model it is the switch that had the model on.
  const whose = !scope ? ""
    : layer === "model" ? (scope === "node" ? " (on by this machine's own setting)" : " (on for every machine)")
      : scope === "node" ? " (this machine's own)" : " (for every machine)";
  const refused = d.decision === "forbidden";
  const auditKey = `audit:${d.ts}:${d.node_id}:${d.cap}.${d.action}`;
  const byBlocklist = layer === "blocklist";
  const cut = (d.cap === "fs" || (d.cap === "exec" && d.action === "run")) && /… \[cut at \d+ of \d+ characters\]$/.test(d.target || "");
  const known = d.cap && d.action && !cut && (d.target || !["exec", "fs"].includes(d.cap));
  const allow = (wildcard, pin) => act(async () => {
    const r = await api("POST", "/api/checker/allow", { cap: d.cap, action: d.action, target: d.target || "", wildcard, node_id: d.node_id, pin: pin ? pin() : null });
    notify(`Added a checker allow rule: ${r.rule}`);
  });
  const pins = pinPicker(d, auditKey);
  return el("div", { class: "card audit-row" },
    itile(byBlocklist ? "ban" : "bot", k.tone || "neutral"),
    el("div", { class: "line" },
      el("b", {}, d.node), el("span", { class: "mono" }, `${d.cap}.${d.action}`),
      pill(k.pill, `${d.decision} by the action checker`),
      el("span", { class: "when", title: when(d.ts) }, ago(d.ts))),
    d.target ? el("code", { class: "target mono" }, d.target) : null,
    detail ? el("p", { class: "meta" }, `${layer === "model" ? "Decision model" : layer === "allow rule" ? "Allow rule" : "Blocklist"}${whose}: ${detail}`) : null,
    refused && !byBlocklist && known ? el("div", { class: "actions" },
      btn("Allow", "", allow(false), "check", `${auditKey}:Allow`), btn("Allow as wildcard", "", allow(true), null, `${auditKey}:Allow as wildcard`)) : null,
    refused && !byBlocklist && known && pins ? el("div", { class: "actions pins" }, pins.root,
      btn("Allow with this value", "", allow(false, pins.pin), null, `${auditKey}:Allow with this value`)) : null,
    byBlocklist ? el("p", { class: "meta" }, scope === "global"
      ? "On the blocklist for every machine (hard deny). To let it through, switch the entry off for this machine (Per machine) or for every machine on the Action checker page."
      : "On the blocklist (hard deny). Remove or switch off the entry on the Action checker page to let it through.") : null);
}

// ---- Action checker (issue #17) ----

const SCOPES = [
  { value: "effects", text: "Execute, write and actuate calls (the default)" },
  { value: "with-reads", text: "Those and reads too" },
  { value: "tainted-only", text: "Only calls of a tainted session" },
];
const SOURCES = [
  { value: "local", text: "A llama-server the center runs" },
  { value: "endpoint", text: "A System One endpoint" },
];
let checkerRun = 0;

// `endsSave`: this load ends the save that asked for it, so the page's
// controls work again before the page is drawn anew (a disabled control
// cannot take the focus back).
async function loadChecker(endsSave) {
  const run = ++checkerRun;
  const [r, o] = await Promise.all([api("GET", "/api/checker"), api("GET", "/api/overview")]);
  if (run !== checkerRun) return;
  // The working copy the form edits; meta holds what does not change here.
  // The fields of per-machine settings are left out when empty.
  const cfg = r.config;
  cfg.nodes = cfg.nodes || {};
  state.checker = { cfg, saved: structuredClone(cfg), meta: r, nodes: o.nodes || [] };
  if (endsSave) endSave();
  if (current() === "checker") draw(true);
}

// Runs a save that no button started (a picker's choice), with the error
// shown as a button's would be, and the focus kept as a button's is.
function quietly(fn) {
  const spot = focusSpot(document.activeElement);
  pendingFocus = spot;
  fn().catch((e) => { if (!e.auth) notify(e.message, "error"); })
    .finally(() => { if (pendingFocus === spot) pendingFocus = null; });
}

function machineName(id) {
  const n = ((state.checker && state.checker.nodes) || []).find((x) => x.id === id);
  return n ? n.name : id;
}

// The machine picker's entries: every machine, then each paired one.
function machineItems() {
  return [{ value: "", text: "Every machine" }, ...((state.checker && state.checker.nodes) || []).map((n) => ({ value: n.id, text: n.name }))];
}

// A save posts the whole working copy, so a second change made while one
// save runs would ride on the first, and be saved although the first was
// refused (and its change taken back). Until a save has settled, the page's
// buttons and switches are off: one save at a time.
let checkerSaving = false;

function lockSaves(on) {
  for (const c of $("page").querySelectorAll("button, input[type=checkbox]")) {
    if (on && !c.disabled) { c.disabled = true; c.dataset.locked = ""; }
    else if (!on && "locked" in c.dataset) { c.disabled = false; delete c.dataset.locked; }
  }
}

function endSave() {
  checkerSaving = false;
  lockSaves(false);
}

// Saves the working copy (or `next`, a copy a handler changed in place of
// it), then reloads so the page shows what the center kept. A handler may
// have changed the working copy before it saved. When the save fails, the
// center kept the old settings, so the working copy goes back to them: the
// next save would otherwise send the change that was refused.
async function saveChecker(next) {
  const c = state.checker;
  checkerSaving = true;
  lockSaves(true);
  try {
    try {
      await api("POST", "/api/checker", { config: next || c.cfg });
    } catch (e) {
      if (!next && state.checker === c) {
        c.cfg = structuredClone(c.saved);
        endSave();
        if (current() === "checker") draw(true);
        if (!e.auth) await loadChecker().catch(() => {});
      }
      throw e;
    }
    await loadChecker(true);
  } finally {
    endSave();
  }
}

function pageChecker() {
  const c = state.checker;
  if (!c) return [loading()];
  const cfg = c.cfg;
  return [
    head("shield", "Action checker", "A gate on the center that checks each call before the machine gets it. The machine's own rules still decide; the checker can only refuse.", [
      [cfg.blocklist_on ? "on" : "off", "blocklist", cfg.blocklist_on ? "ok" : ""],
      [cfg.model_on ? "on" : "off", "model", cfg.model_on ? "ok" : ""],
    ]),
    section("Switches", "Each part has its own switch; a change takes effect for the next call.", null, el("div", { class: "card" },
      checkerToggle("blocklist_on", "Blocklist (deterministic, on by default)", cfg.blocklist_on, (v) => { cfg.blocklist_on = v; }),
      checkerToggle("model_on", "Decision model (off by default)", cfg.model_on, (v) => { cfg.model_on = v; }),
      checkerToggle("taint_on", "Taint marking (a session is tainted after a call returns content)", cfg.taint_on, (v) => { cfg.taint_on = v; }))),
    c.meta.rejected && c.meta.rejected.length ? banner("warn", "alert", `Some rules do not parse and were left out: ${c.meta.rejected.join("; ")}`) : null,
    c.meta.unpublished && c.meta.unpublished.length ? banner("warn", "alert", `Some rules name a capability no machine offers, so they match no call now (a typo, or a capability that is gone): ${c.meta.unpublished.join("; ")}`) : null,
    staleBanner(c.meta.stale),
    blocklistCard(cfg, c.meta),
    allowCard(cfg),
    machinesCard(cfg),
    modelCard(cfg, c.meta),
  ];
}

// The rules whose conditions no longer fit the arguments their action
// takes now (an argument gone, or of another type), each with why. They
// fail closed until the owner changes them.
function staleBanner(stale) {
  const list = Object.entries(stale || {});
  if (!list.length) return null;
  return banner("warn", "alert", `Some rules no longer fit what their action takes (an argument gone or of another type, a value it no longer takes): on the blocklist such a rule may refuse calls it was not meant for, as an allow rule it may not cover the calls it was meant for. Change or remove them: ${list.map(([r, why]) => `${r} (${why})`).join("; ")}`);
}

// Under a rule field: the arguments the action typed so far takes, which a
// rule may pin after its colon (room=office, brightness<=50), from what the
// machines publish. The center checks the rule against them when it saves.
function ruleFieldsHint(input) {
  const hint = el("p", { class: "hint", "aria-live": "polite" });
  const show = () => {
    const scope = input.value.trim().split(":")[0];
    const fields = ((state.checker && state.checker.meta.fields) || {})[scope];
    hint.textContent = fields && fields.length
      ? `${scope} takes ${fields.join(", ")}. Pin them after a colon, joined by commas: ${scope}:${fields[0].split(" ")[0]}=…`
      : "";
  };
  input.addEventListener("input", show);
  show();
  return hint;
}

// A switch that mutates the working copy and saves at once.
function checkerToggle(field, label, on, apply) {
  const input = el("input", { type: "checkbox", role: "switch", "data-focus": `switch:${field}`, onchange: act(async (ev) => { apply(ev.currentTarget.checked); await saveChecker(); }) });
  input.checked = !!on;
  return el("label", { class: "switch" }, input, el("span", {}, label));
}

// One blocklist entry: its switch, rule, scope (every machine, with the
// machines it is switched off for, or one machine) and note. `where` is the
// list it is shown in (the blocklist, or a machine's card), so that its
// controls are named once on the page; the entry is named by what it is, not
// by its place in the list: a built-in by its id, so an owner entry with the
// same rule is never taken for it, an own entry by its rule, scope and note.
// Entries that are still alike share a key, which focusSpot treats as none.
function blockRow(cfg, e, i, where) {
  const key = `block:${where}:${e.id ? `id=${e.id}` : `${e.rule}|${e.node_id || ""}|${e.note || ""}`}`;
  const t = el("input", { type: "checkbox", role: "switch", "data-focus": `${key}:switch`, onchange: act(async (ev) => { cfg.blocklist[i].on = ev.currentTarget.checked; await saveChecker(); }) });
  t.checked = e.on;
  const off = e.off_for || [];
  return el("div", { class: "card entry" },
    el("div", { class: "card-top" },
      el("label", { class: "switch" }, t, el("code", { class: "mono" }, e.rule)),
      e.builtin ? pill("", "default") : null,
      pill("", e.node_id ? `only ${machineName(e.node_id)}` : "every machine"),
      off.length ? pill("warn", `off for ${off.map(machineName).join(", ")}`) : null,
      el("span", { class: "push" }, btn("Remove", "danger-soft", act(async () => { cfg.blocklist.splice(i, 1); await saveChecker(); }), "trash", `${key}:remove`))),
    e.note ? el("p", { class: "meta" }, e.note) : null);
}

function blocklistCard(cfg, meta) {
  const ruleIn = el("input", { class: "input mono", placeholder: "exec.run:rm -rf /*  or  fs.write:/etc/sudoers", "aria-label": "New blocklist rule", "data-focus": "blocklist:rule" });
  const noteIn = el("input", { class: "input", placeholder: "What it guards against (optional)", "aria-label": "Note", "data-focus": "blocklist:note" });
  const items = machineItems();
  let blockNode = "";
  const nodePicker = picker({ label: "For", search: "Search machines", none: "No machine matches.", onpick: (v) => { blockNode = v; nodePicker.set(items, v); } });
  nodePicker.set(items, "");
  const add = act(async () => {
    const rule = ruleIn.value.trim();
    if (!rule) { notify("Enter a rule.", "error"); return; }
    cfg.blocklist.push({ rule, on: true, builtin: false, note: noteIn.value.trim(), node_id: blockNode || null });
    ruleIn.value = ""; noteIn.value = "";
    await saveChecker();
  });
  const reset = act(async () => {
    const yes = await modal({ title: "Reset the blocklist?", message: "This replaces the whole blocklist with the built-in defaults, for every machine; your own entries (also those for one machine), entries you switched off, and entries switched off for single machines are lost.", confirm: "Reset", danger: true });
    if (!yes) return;
    cfg.blocklist = meta.default_blocklist.map((e) => ({ ...e }));
    await saveChecker();
  });
  return section("Blocklist", "Exact commands or wildcards that are refused at once, in the machine's own rule syntax (exec.run:…, fs.write:…), for every machine or for one. A re: regex form is allowed where a glob is not enough. An fs.read: or fs.write: path also holds the paths any other capability reads or writes. Any other action is named whole (lamp.set, or lamp for all its actions), or with conditions on its arguments (lamp.set:room=office,brightness>50); a call that gives such an argument another type, or leaves it out, is refused too. The blocklist wins over the allow rules and the model. An entry for every machine can be switched off for single machines under Per machine.", btn("Reset to defaults", "ghost", reset, "refresh", "blocklist:reset"),
    el("div", { class: "card" }, el("div", { class: "form-row" },
      el("label", { class: "field grow" }, el("span", { class: "label" }, "Add a rule"), ruleIn, ruleFieldsHint(ruleIn)),
      el("label", { class: "field grow" }, el("span", { class: "label" }, "Note"), noteIn),
      nodePicker.root),
      el("div", { class: "actions" }, el("button", { type: "button", class: "btn primary", "data-focus": "blocklist:add", onclick: add }, icon("plus", "sm"), "Add"))),
    el("p", { class: "meta" }, "What the matcher cannot see: shell variables, aliases, a script written then run, and base64. The decision model and the machine's policy are the next lines of defence."),
    cfg.blocklist.length ? el("div", { class: "list" }, cfg.blocklist.map((e, i) => blockRow(cfg, e, i, "all"))) : empty("The blocklist is empty.", "shield"));
}

// One saved allow rule, with its scope.
function allowRow(cfg, a, i, where) {
  return el("div", { class: "card entry" },
    el("div", { class: "card-top" },
      el("code", { class: "mono" }, a.rule),
      pill("", a.node_id ? `only ${machineName(a.node_id)}` : "every machine"),
      el("span", { class: "push" }, btn("Remove", "danger-soft", act(async () => { cfg.allow_rules.splice(i, 1); await saveChecker(); }), "trash", `allow:${where}:${a.rule}|${a.node_id || ""}:remove`))));
}

function allowCard(cfg) {
  const ruleIn = el("input", { class: "input mono", placeholder: "exec.run:docker exec *", "aria-label": "New allow rule", "data-focus": "allow:rule" });
  const nodeItems = machineItems();
  let allowNode = "";
  const nodePicker = picker({ label: "For", search: "Search machines", none: "No machine matches.", onpick: (v) => { allowNode = v; nodePicker.set(nodeItems, v); } });
  nodePicker.set(nodeItems, "");
  const add = act(async () => {
    const rule = ruleIn.value.trim();
    if (!rule) { notify("Enter a rule.", "error"); return; }
    cfg.allow_rules.push({ rule, node_id: allowNode || null });
    ruleIn.value = "";
    await saveChecker();
  });
  return section("Allow rules", "A call that matches an allow rule skips the decision model and goes straight to the machine. It does not skip the blocklist. A command rule covers a line only when every command in it meets the rule, with no flag or operand the rule does not name (but after a bare *), no wrapper with words of its own (env A=B, sudo -u), and nothing run inside another command ($( ), sh -c, env -S); a re: rule covers a line of one command; exec.run:exact:… covers one line exactly.", null,
    el("div", { class: "card" }, el("div", { class: "form-row" },
      el("label", { class: "field grow" }, el("span", { class: "label" }, "Add a rule"), ruleIn, ruleFieldsHint(ruleIn)),
      nodePicker.root),
      el("div", { class: "actions" }, el("button", { type: "button", class: "btn primary", "data-focus": "allow:add", onclick: add }, icon("plus", "sm"), "Add"))),
    cfg.allow_rules.length ? el("div", { class: "list" }, cfg.allow_rules.map((a, i) => allowRow(cfg, a, i, "all"))) : empty("No allow rules.", "shield"));
}

// ---- Per machine: the switches, entries, exceptions and allow rules of
// one machine (owner's decision of 2026-10-18) ----

// The machines whose card is open, so a save (which redraws the page) keeps
// them open.
const checkerOpen = new Set();

// The paired machines, and any machine the settings still name although it
// is no longer paired, so its settings can be forgotten.
function checkerMachines(cfg) {
  const nodes = (state.checker && state.checker.nodes) || [];
  const named = new Set(Object.keys(cfg.nodes || {}));
  for (const e of cfg.blocklist) {
    if (e.node_id) named.add(e.node_id);
    for (const id of e.off_for || []) named.add(id);
  }
  for (const a of cfg.allow_rules) if (a.node_id) named.add(a.node_id);
  const gone = [...named].filter((id) => !nodes.some((n) => n.id === id));
  return [...nodes.map((n) => ({ id: n.id, name: n.name, paired: true })), ...gone.map((id) => ({ id, name: id, paired: false }))];
}

function machinesCard(cfg) {
  const machines = checkerMachines(cfg);
  return section("Per machine", "Each machine follows the center's switches unless you set the blocklist or the model on or off for it. It can have block entries of its own, and switch single entries for every machine off for itself. A block anywhere wins: the center's blocklist, this machine's entries, or the machine's own deny list; an allow rule only skips the model.", null,
    machines.length ? el("div", { class: "stack" }, machines.map((m) => machineCard(cfg, m))) : empty("No machine is paired.", "server"));
}

function machineCard(cfg, m) {
  const own = cfg.nodes[m.id] || { blocklist: "inherit", model: "inherit" };
  const indexed = cfg.blocklist.map((e, i) => [e, i]);
  const entries = indexed.filter(([e]) => e.node_id === m.id);
  const offs = indexed.filter(([e]) => !e.node_id && (e.off_for || []).includes(m.id));
  const others = indexed.filter(([e]) => !e.node_id && !(e.off_for || []).includes(m.id));
  const allows = cfg.allow_rules.map((a, i) => [a, i]).filter(([a]) => a.node_id === m.id);

  // The blocklist or model setting: as the center, or on or off here.
  const switchPicker = (part, label, centerOn) => {
    const items = [
      { value: "inherit", text: `As the center (${centerOn ? "on" : "off"})` },
      { value: "on", text: "On for this machine" },
      { value: "off", text: "Off for this machine" },
    ];
    const p = picker({
      label, search: "Search", none: "No match.", key: `node:${m.id}:${part}`,
      onpick: (v) => { p.set(items, v); cfg.nodes[m.id] = { ...own, [part]: v }; quietly(saveChecker); },
    });
    p.set(items, own[part] || "inherit");
    return p.root;
  };

  const exceptItems = [{ value: "", text: "Pick an entry for every machine" },
    ...others.map(([e, i]) => ({ value: String(i), text: e.note ? `${e.note}: ${e.rule}` : e.rule }))];
  const exceptPicker = picker({
    label: "Switch off for this machine", search: "Search entries", none: "No entry matches.", key: `node:${m.id}:except`,
    onpick: (v) => {
      exceptPicker.set(exceptItems, v);
      if (v === "") return;
      const e = cfg.blocklist[Number(v)];
      e.off_for = [...(e.off_for || []), m.id];
      quietly(saveChecker);
    },
  });
  exceptPicker.set(exceptItems, "");
  const offRow = ([e]) => el("div", { class: "card entry" },
    el("div", { class: "card-top" },
      el("code", { class: "mono" }, e.rule),
      el("span", { class: "push" }, btn("Switch on again", "", act(async () => { e.off_for = (e.off_for || []).filter((id) => id !== m.id); await saveChecker(); }), null, `off:${m.id}:${e.id ? `id=${e.id}` : `${e.rule}|${e.node_id || ""}|${e.note || ""}`}:on`))),
    e.note ? el("p", { class: "meta" }, e.note) : null);

  const ruleIn = el("input", { class: "input mono", placeholder: "exec.run:terraform destroy*", "aria-label": `New blocklist rule for ${m.name}`, "data-focus": `node:${m.id}:rule` });
  const add = act(async () => {
    const rule = ruleIn.value.trim();
    if (!rule) { notify("Enter a rule.", "error"); return; }
    cfg.blocklist.push({ rule, on: true, builtin: false, note: "", node_id: m.id });
    ruleIn.value = "";
    await saveChecker();
  });
  // A machine no longer paired: drop everything the settings hold for it.
  const forget = act(async () => {
    delete cfg.nodes[m.id];
    cfg.blocklist = cfg.blocklist.filter((e) => e.node_id !== m.id).map((e) => ({ ...e, off_for: (e.off_for || []).filter((id) => id !== m.id) }));
    cfg.allow_rules = cfg.allow_rules.filter((a) => a.node_id !== m.id);
    checkerOpen.delete(m.id);
    await saveChecker();
  });

  // The owner's note: the owner's own words about the machine, which list()
  // shows the agent. The center keeps it on one line.
  // The center counts the note in UTF-8 bytes, and `maxlength` counts
  // characters: an umlaut or a dash takes more than one byte, so the field
  // counts bytes itself and keeps a note that is too long rather than
  // sending it.
  const noteBytes = () => new TextEncoder().encode(noteIn.value.trim()).length;
  const noteLeft = el("span", { class: "meta" });
  const showLeft = () => {
    const n = noteBytes();
    noteLeft.textContent = n > NOTE_MAX ? `${n - NOTE_MAX} bytes too long` : `${NOTE_MAX - n} bytes left`;
  };
  const noteIn = el("input", { class: "input", type: "text", maxlength: String(NOTE_MAX), value: own.note || "", placeholder: "test VM; its databases hold throwaway data", "aria-label": `Note on ${m.name}`, "data-focus": `node:${m.id}:note`, oninput: showLeft });
  showLeft();
  const saveNote = act(async () => {
    const n = noteBytes();
    if (n > NOTE_MAX) { notify(`The note is ${n} bytes long; at most ${NOTE_MAX} fit.`, "error"); return; }
    cfg.nodes[m.id] = { ...own, note: noteIn.value.trim() };
    await saveChecker();
  });

  const word = (v) => (v === "on" ? "on here" : "off here");
  const body = el("div", { class: "body" },
    el("div", { class: "form-row" },
      switchPicker("blocklist", "Blocklist", cfg.blocklist_on),
      switchPicker("model", "Decision model", cfg.model_on)),
    el("p", { class: "meta" }, "The model on here uses the center's one model and its settings below. Taint is for every machine."),
    el("h4", { class: "sub-head" }, "Your note on this machine"),
    el("p", { class: "meta" }, "A few words for the agent, such as what the machine is for. list() shows them to every harness of this center as your words, next to the machine. One line, at most 400 bytes."),
    el("div", { class: "form-row" }, el("label", { class: "field grow" }, el("span", { class: "label" }, "Note"), noteIn, noteLeft)),
    el("div", { class: "actions" }, btn("Save note", "primary", saveNote, null, `node:${m.id}:note:save`)),
    el("h4", { class: "sub-head" }, "Block entries for this machine only"),
    entries.length ? el("div", { class: "list" }, entries.map(([e, i]) => blockRow(cfg, e, i, m.id))) : el("p", { class: "meta" }, "None."),
    el("div", { class: "form-row" }, el("label", { class: "field grow" }, el("span", { class: "label" }, "Add a rule for this machine"), ruleIn, ruleFieldsHint(ruleIn))),
    el("div", { class: "actions" }, el("button", { type: "button", class: "btn primary", "data-focus": `node:${m.id}:add`, onclick: add }, icon("plus", "sm"), "Add")),
    el("h4", { class: "sub-head" }, "Entries for every machine, switched off here"),
    offs.length ? el("div", { class: "list" }, offs.map(offRow)) : el("p", { class: "meta" }, "None."),
    el("div", { class: "form-row" }, exceptPicker.root),
    el("h4", { class: "sub-head" }, "Allow rules for this machine only"),
    allows.length ? el("div", { class: "list" }, allows.map(([a, i]) => allowRow(cfg, a, i, m.id))) : el("p", { class: "meta" }, "None. Add one under Allow rules."),
    m.paired ? null : el("div", { class: "actions" }, btn("Forget its settings", "danger-soft", forget, "trash", `node:${m.id}:forget`)));
  const card = el("details", { class: "card", ontoggle: (ev) => { if (ev.currentTarget.open) checkerOpen.add(m.id); else checkerOpen.delete(m.id); } },
    el("summary", {}, el("span", { class: "name" }, m.name),
      m.paired ? null : pill("down", "not paired"),
      own.blocklist && own.blocklist !== "inherit" ? pill(own.blocklist === "on" ? "up" : "warn", `blocklist ${word(own.blocklist)}`) : null,
      own.model && own.model !== "inherit" ? pill(own.model === "on" ? "up" : "warn", `model ${word(own.model)}`) : null,
      own.note ? pill("", "note") : null,
      entries.length ? pill("", plural(entries.length, "own entry", "own entries")) : null,
      offs.length ? pill("warn", `${offs.length} switched off`) : null,
      icon("chev", "sm chev")),
    body);
  // Set after the build: el() would read an "open" attribute as an "on…" handler.
  if (checkerOpen.has(m.id)) card.open = true;
  return card;
}

function modelCard(cfg, meta) {
  const m = cfg.model;
  let source = m.source;
  const srcPicker = picker({ label: "Source", search: "Search", none: "No match.", key: "model:source", onpick: (v) => { source = v; srcPicker.set(SOURCES, v); showSource(); } });
  srcPicker.set(SOURCES, source);
  const endpointUrl = el("input", { class: "input mono", value: m.endpoint_url, "data-focus": "model:endpoint_url", placeholder: "https://host:9931" });
  const endpointModel = el("input", { class: "input mono", value: m.endpoint_model, "data-focus": "model:endpoint_model", placeholder: "jev-latest (optional)" });
  const token = el("input", { class: "input", type: "password", "data-focus": "model:token", placeholder: meta.has_token ? "a token is set — type to replace" : "optional bearer token", autocomplete: "off" });
  const threshold = el("input", { class: "input num", type: "number", min: "0", max: "1", step: "0.01", value: m.threshold, "data-focus": "model:threshold" });
  const timeout = el("input", { class: "input num", type: "number", min: "100", value: m.timeout_ms, "data-focus": "model:timeout" });
  let scope = m.scope;
  const scopePicker = picker({ label: "Which calls the model sees", search: "Search", none: "No match.", key: "model:scope", onpick: (v) => { scope = v; scopePicker.set(SCOPES, v); } });
  scopePicker.set(SCOPES, scope);
  const failClosed = el("input", { type: "checkbox", role: "switch", "data-focus": "switch:fail_closed" }); failClosed.checked = m.fail_closed;
  const instr = el("textarea", { class: "json", rows: "4", "data-focus": "model:instructions" }, m.instructions);
  const critTrue = el("input", { class: "input", value: m.criteria_true, "data-focus": "model:criteria_true" });
  const critFalse = el("input", { class: "input", value: m.criteria_false, "data-focus": "model:criteria_false" });
  const save = act(async () => {
    // The form's values go into a copy: a refused save leaves the working
    // copy as it was, and the form keeps what was typed.
    const next = { ...cfg, model: {
      ...m,
      source,
      endpoint_url: endpointUrl.value.trim(),
      endpoint_model: endpointModel.value.trim(),
      threshold: Number(threshold.value),
      timeout_ms: Number(timeout.value),
      scope,
      fail_closed: failClosed.checked,
      instructions: instr.value,
      criteria_true: critTrue.value,
      criteria_false: critFalse.value,
    } };
    if (token.value) { await api("POST", "/api/checker/token", { token: token.value }); token.value = ""; }
    await saveChecker(next);
    notify("Saved.");
  });
  const resetQuestion = () => { instr.value = ""; critTrue.value = ""; critFalse.value = ""; notify("Cleared; Save to store the defaults."); };
  const field = (label, input) => el("label", { class: "field grow" }, el("span", { class: "label" }, label), input);
  const epDiv = el("div", {},
    el("div", { class: "form-row" }, field("Endpoint URL", endpointUrl), field("Model name", endpointModel)),
    el("div", { class: "form-row" }, field("Bearer token (kept secret, never shown back)", token),
      meta.has_token ? el("span", { class: "push" }, btn("Clear token", "ghost", act(async () => { await api("POST", "/api/checker/token", { token: null }); await loadChecker(); }), "trash", "model:clear-token")) : null));
  const localDiv = el("div", {}, ...localInstall(meta));
  const showSource = () => { epDiv.hidden = source !== "endpoint"; localDiv.hidden = source !== "local"; };
  showSource();
  return section("Decision model", "An optional System One model that answers, in one pass, whether a call is dangerous. At or above the threshold the call is refused. An unreachable model refuses the call (fail closed) unless you switch that off below.", null,
    el("div", { class: "card" },
      el("div", { class: "form-row" }, srcPicker.root),
      epDiv,
      localDiv,
      el("div", { class: "form-row" }, field("Threshold (0 to 1)", threshold), field("Timeout (ms)", timeout)),
      el("div", { class: "form-row" }, scopePicker.root),
      el("label", { class: "switch" }, failClosed, el("span", {}, "Fail closed: refuse a call when the model is unreachable (recommended). Off: allow and log it.")),
      el("div", { class: "form-row" }, field("Question (the command text is never put here; it goes only in the state sent to the model)", instr)),
      el("div", { class: "form-row" }, field("When true (dangerous)", critTrue), field("When false (safe)", critFalse)),
      el("div", { class: "actions" },
        el("button", { type: "button", class: "btn primary", "data-focus": "model:save", onclick: save }, "Save"),
        btn("Reset the question", "ghost", resetQuestion, "refresh"))));
}

// The local model: a one-click install of llama.cpp and the chosen model
// (d1-2B by default, or Kev-4B), then the running status. The model picker
// stays outside the polled container, so a poll does not close it; the
// container is refreshed in place without rebuilding the form.
let checkerStatusEl = null;
let checkerPick = null;
const INSTALLING = ["downloading", "unpacking", "verifying"];
const gb = (bytes) => `${(bytes / 1e9).toFixed(1)} GB`;

function localInstall(meta) {
  const running = state.checker.cfg.model.local_model;
  if (!checkerPick) checkerPick = running;
  const items = meta.models.map((m, i) => ({ value: m.id, text: m.name + (i === 0 ? " (the default)" : "") }));
  const p = picker({
    label: "Model", search: "Search models", none: "No model matches.",
    onpick: (v) => { checkerPick = v; p.set(items, v); checkerStatusEl.replaceChildren(...localInstallParts(state.checker.meta)); },
  });
  p.set(items, checkerPick);
  checkerStatusEl = el("div", {});
  checkerStatusEl.replaceChildren(...localInstallParts(meta));
  return [
    el("p", { class: "meta" }, "The center downloads and runs llama.cpp and the model itself, in its own state folder. Pick the model here; the device (CPU or GPU) is separate."),
    el("div", { class: "form-row" }, p.root),
    checkerStatusEl,
  ];
}

const bar = (p) => {
  const pct = p && p.total ? Math.min(100, Math.round((100 * p.done) / p.total)) : 0;
  return el("div", { class: "pbar" }, el("div", { class: "pfill", style: `width:${pct}%` }), el("span", { class: "pct" }, `${pct}%`));
};

// What the local model part shows. The builders below leave a part out as
// null, which replaceChildren would print as the word.
function localInstallParts(meta) {
  return localInstallBlocks(meta).filter((p) => p != null);
}

function localInstallBlocks(meta) {
  const pin = meta.models.find((m) => m.id === checkerPick) || meta.models[0];
  // One plain line per model, so the choice is informed: size, licence, and
  // the measured speed and quality.
  const line = el("p", { class: "meta" }, `${pin.name}: ${gb(pin.bytes)}, licence ${pin.licence}. ${pin.summary}`);
  if (!meta.platform_supported) {
    return [line, banner("warn", "alert", "This machine has no prebuilt local model for it. Use a System One endpoint instead (the other source above).")];
  }
  const inst = meta.install || { phase: "idle" };
  const installing = INSTALLING.includes(inst.phase);
  // Also offered while an install runs, so a slow download can be stopped
  // from the page: Remove ends the install first.
  const remove = btn("Remove", "danger-soft", act(async () => {
    const yes = await modal({
      title: installing ? "Stop the install and remove the local model?" : "Remove the local model?",
      message: installing
        ? `Ends the install and deletes the downloaded llama.cpp and model files${meta.installed ? ", also those of the model installed now" : ""}. You can install them again later.`
        : "Deletes the downloaded llama.cpp and model files. You can install them again later.",
      confirm: "Remove", danger: true,
    });
    if (yes) { await api("POST", "/api/checker/remove"); await loadChecker(); }
  }), "trash", "local:remove");
  if (installing) {
    const target = meta.models.find((m) => m.id === inst.model_id) || pin;
    return [line, el("div", { class: "card" },
      el("div", { class: "card-top" }, icon("download"), el("span", { class: "name" }, `Installing ${target.name}`), pill("warn", inst.phase)),
      el("p", { class: "meta" }, "llama.cpp"), bar(inst.llama),
      el("p", { class: "meta" }, `model (${gb(target.bytes)})`), bar(inst.model),
      inst.message ? el("p", { class: "meta" }, inst.message) : null,
      meta.local ? el("p", { class: "meta" }, "The installed model keeps checking calls until the new files are in place; it is stopped only for the swap at the end.") : null,
      el("div", { class: "actions" }, remove))];
  }
  const cfg = state.checker.cfg.model;
  const failed = inst.phase === "failed" ? banner("down", "alert", `The last install failed: ${inst.message || "unknown error"}`) : null;
  if (meta.installed && pin.id === cfg.local_model) {
    const dev = cfg.local_gpu ? "GPU" : "CPU";
    const other = dev === "GPU" ? "CPU" : "GPU";
    const reinstall = (gpu) => act(async () => { await api("POST", "/api/checker/install", { gpu, model: pin.id }); await loadChecker(); });
    return [line, failed,
      el("div", { class: "actions" },
        el("span", { class: "meta" }, `Installed, running on the ${dev}.`),
        meta.gpu_hint || dev === "GPU" ? btn(`Switch to ${other}`, "ghost", reinstall(other === "GPU")) : null,
        remove),
      ...localStatusParts(meta.local, meta.model_wanted)];
  }
  const current = meta.installed ? meta.models.find((m) => m.id === cfg.local_model) : null;
  return [line, failed,
    current ? el("p", { class: "meta" }, `Installed now: ${current.name}. Switching downloads ${pin.name} (${gb(pin.bytes)}) and removes it; the threshold and timeout become ${pin.name.split(" (")[0]}'s defaults (${pin.threshold}, ${pin.timeout_ms / 1000} s).`) : null,
    installButtons(meta, pin, current ? "Switch" : "Install"),
    current ? el("div", { class: "actions" }, remove) : null];
}

function installButtons(meta, pin, verb) {
  const install = (gpu) => act(async () => { await api("POST", "/api/checker/install", { gpu, model: pin.id }); await loadChecker(); });
  return el("div", { class: "actions" },
    btn(`${verb} on CPU`, "primary", install(false), "download"),
    meta.gpu_hint ? btn(`${verb} on GPU`, "primary", install(true), "download") : null,
    el("span", { class: "meta" }, meta.gpu_hint ? "GPU uses the Vulkan build (NVIDIA, AMD or Intel)." : "No GPU detected; CPU only."));
}

// `wanted` is the center's word on whether the model is on anywhere: by the
// center's switch or for a single machine, the same rule that decides
// whether the local model runs.
function localStatusParts(s, wanted) {
  if (!s) {
    return [el("p", { class: "meta" }, wanted
      ? "The model is on but its server is not running. The Log page says why."
      : "The model is installed but not running. Turn the model on (the switch at the top, or for a machine under Per machine).")];
  }
  const tone = s.phase === "ready" ? "up" : s.phase === "failed" ? "down" : "warn";
  return [el("div", { class: "card" },
    el("div", { class: "card-top" }, el("span", { class: "dot" + (s.phase === "ready" ? " up" : "") }), el("span", { class: "name" }, "Local model"), pill(tone, s.phase)),
    s.url ? el("p", { class: "meta mono" }, s.url) : null,
    s.message ? el("p", { class: "meta" }, s.message) : null,
    s.output && s.output.length ? el("pre", { class: "logbox mono" }, s.output.join("\n")) : null)];
}

// Polls the install progress and the running status, so the page shows them
// move along without rebuilding the form. A phase change that adds or removes
// buttons (install finished, removed) triggers one redraw.
async function pollCheckerLocal() {
  if (!state.checker || !checkerStatusEl) return;
  const r = await api("GET", "/api/checker");
  if (current() !== "checker" || !checkerStatusEl) return;
  const was = state.checker.meta;
  const changed = was.installed !== r.installed
    || (was.install && was.install.phase) !== (r.install && r.install.phase)
    || JSON.stringify(was.installed_models) !== JSON.stringify(r.installed_models);
  state.checker.meta = r;
  // An install that finished or a removal changes the config (model, device,
  // threshold) as well: reload it all, not just the status.
  if (changed) { await loadChecker(); return; }
  checkerStatusEl.replaceChildren(...localInstallParts(r));
}

// ---- Capabilities ----

// What a machine offers the agent and where each unit comes from, and the
// capabilities this center added there itself (docs/user/web-ui.md). A
// machine that gave this center the settings grant (write) takes changes:
// add, edit, remove. One without it is shown read only.
const CAP_EFFECTS = ["read", "write", "execute", "sense", "actuate"];
const CAP_PLATFORMS = ["any", "linux", "windows"];
let capsRun = 0;

// The picker is made once and kept, as the statistics page's. It stays on
// the page while the machine picked loads, so another one can be picked.
const capsPicker = picker({
  label: "Machine", search: "Search machines", none: "No machine matches.", key: "caps:machine",
  onpick: (id) => {
    state.capsNode = id;
    if (state.caps) state.caps = { nodes: state.caps.nodes, data: null, form: null };
    draw(true);
    loadCaps().catch((e) => { if (!e.auth) notify(e.message, "error"); });
  },
});

// `fresh` reads the machines again, not the overview the poll keeps.
async function loadCaps(fresh) {
  const run = ++capsRun;
  const o = (!fresh && state.overview) || await api("GET", "/api/overview");
  const nodes = o.nodes || [];
  if (!nodes.some((n) => n.id === state.capsNode)) state.capsNode = nodes.length ? nodes[0].id : null;
  if (state.capsNode === null) {
    state.caps = { nodes, data: null, form: null };
  } else {
    let data;
    try {
      data = await api("GET", `/api/caps?id=${encodeURIComponent(state.capsNode)}`);
    } catch (e) {
      if (e.auth) throw e;
      // A machine picked since then has its own load: this one's error
      // is not about the page shown.
      if (run !== capsRun) return;
      // A machine removed meanwhile is still in the list the page has:
      // the list is read again, and the first machine left is shown.
      if (e.status === 404 && !fresh) {
        notify(e.message, "error");
        return loadCaps(true);
      }
      state.caps = { nodes, data: null, failed: e.message, form: null };
      if (current() === "capabilities") draw(true);
      return;
    }
    if (run !== capsRun) return;
    // An open form stays open over a reload.
    state.caps = { nodes, data, form: state.caps && state.caps.form };
  }
  if (current() === "capabilities") draw(true);
}

function pageCaps() {
  const c = state.caps;
  if (!c) return [loading()];
  const head_ = head("plug", "Capabilities", "What each machine offers the agent, where it comes from, and the capabilities this center added there itself.");
  if (!c.nodes.length) return [head_, empty("No machines yet.", "server")];
  capsPicker.set(c.nodes.map((n) => ({ value: n.id, text: n.name })), state.capsNode);
  const d = c.data;
  if (!d) {
    return [head_, el("div", { class: "picker-row" }, capsPicker.root),
      c.failed ? banner("error", "alert", `The machine's capabilities did not load: ${c.failed}`) : loading()];
  }
  return [head_, el("div", { class: "picker-row" }, capsPicker.root),
    !d.online ? banner("warn", "alert", "This machine is offline: the list is what it offered when it was last linked.") : null,
    !d.settings_write ? banner("info", "info", "This machine does not let this center change its settings (settings grant off), so it is shown read only. Its owner gives the grant with nerve-node center settings on.") : null,
    section("Offered", "Each unit the agent may be offered here, with what it does and where it comes from.", null,
      d.units.length ? el("div", { class: "list" }, d.units.map(capUnitRow)) : empty("This machine offers no capability to the agent now.", "plug")),
    d.broken.length ? section("Left out", "Units the center does not offer the agent, with the reason.", null,
      el("div", { class: "list" }, d.broken.map((b) => el("div", { class: "card cap-row" },
        el("div", { class: "card-top" }, el("code", { class: "mono name" }, b.name), pill("down", "left out")),
        el("p", { class: "meta" }, b.reason))))) : null,
    d.settings_write ? addedSection(d) : null];
}

// What a unit does, in a tone: one that senses or acts on the world stands
// out, as the owner turns it on.
function effectPill(effect) {
  return pill(effect === "sense" || effect === "actuate" ? "warn" : effect === "read" ? "" : "accent", effect);
}

function capUnitRow(u) {
  return el("div", { class: "card cap-row" },
    el("div", { class: "card-top" },
      el("code", { class: "mono name" }, u.name),
      effectPill(u.effect),
      u.kind !== "action" ? pill("", u.kind) : null,
      u.off ? pill("down", "off") : null,
      el("span", { class: "meta push" }, u.source)),
    u.summary ? el("p", { class: "meta" }, u.summary) : null);
}

// The capabilities this center added on the machine, and the form to add
// or change one. The machine says when it takes none (Windows for now, or
// one run by hand) and why.
function addedSection(d) {
  const a = d.added;
  const c = state.caps;
  const sub = "Each runs a fixed command as nerve-run, counts as execute whatever it says it does, and only the machine's owner turns on one that senses or actuates. The owner can turn any of them off or remove it.";
  if (!d.online || !a) return section("Added by this center", sub, null, el("p", { class: "meta" }, "The machine is offline; its capabilities can be changed when it is back."));
  if (a.error) return section("Added by this center", sub, null, banner("error", "alert", `The machine did not say: ${a.error}`));
  const add = a.refused ? null : btn("Add a capability", "primary", () => { c.form = { adding: true, form: blankCapForm() }; draw(true); }, "plus", "caps:add");
  const entries = a.entries || [];
  return section("Added by this center", sub, add,
    a.refused ? banner("warn", "alert", `This machine takes no capability from a center: ${a.refused}.`) : null,
    c.form ? capForm(d, c.form) : null,
    entries.length ? el("div", { class: "list" }, entries.map((e) => addedRow(d, e))) : (a.refused ? null : el("p", { class: "meta" }, "None yet.")));
}

// Why the machine does not offer one this center added, where it is not
// left out: its policy decides it as a command, so in folder mode it needs an
// on and in allowlist mode an allow rule, and one that senses or actuates
// waits for the owner. The machine leaves it out of the description then.
// The center sets either for that action by its name only: the machine
// keeps its capability as a whole for the owner, as a program the owner
// allows may offer more under it later.
function notOffered(d, e) {
  if (e.left_out || d.units.some((u) => u.name === e.name)) return null;
  const why = e.effect === "sense" || e.effect === "actuate"
    ? `only the machine's owner turns it on, with nerve-node cap set ${e.name} on --center and this center's name on that machine.`
    : `the machine's policy does not let the agent use it yet. Turn it on in Settings › Machines, by its full name: in folder mode with an on for it ("caps": {"${e.name}": "on"}), in allowlist mode with the allow rule ${e.name}. An off the owner set stays.`;
  return el("p", { class: "meta" }, `Not offered now: ${why}`);
}

function addedRow(d, e) {
  const c = state.caps;
  const idle = notOffered(d, e);
  return el("div", { class: "card cap-row" },
    el("div", { class: "card-top" },
      el("code", { class: "mono name" }, e.name),
      effectPill(e.effect),
      e.effect === "sense" || e.effect === "actuate" ? null : el("span", { class: "meta" }, "counted as execute"),
      e.left_out ? pill("down", "left out") : null,
      idle ? pill("warn", "not offered") : null,
      el("span", { class: "push" }),
      btn("Edit", "ghost", () => { c.form = { adding: false, form: { ...e.form } }; draw(true); }, "edit", `cap:${e.name}:edit`),
      btn("Remove", "ghost", act(async () => {
        const yes = await modal({ title: `Remove ${e.name}?`, message: "The agent is no longer offered it on this machine.", confirm: "Remove", danger: true });
        if (!yes) return;
        await api("POST", "/api/caps/remove", { id: d.node.id, name: e.name });
        notify(`Removed ${e.name}.`);
        await loadCaps();
      }), "trash", `cap:${e.name}:remove`)),
    e.summary ? el("p", { class: "meta" }, e.summary) : null,
    el("p", { class: "meta" }, el("code", { class: "mono" }, e.form.command)),
    e.left_out ? el("p", { class: "meta" }, `Left out: ${e.left_out}`) : null,
    idle);
}

function blankCapForm() {
  return { name: "", summary: "", effect: "read", command: "", params: "", result: "", timeout: "", platform: "any" };
}

// The form of a capability: each field says what is wrong with it while it
// is typed in, checked by the center with the machine's own rules
// (/api/caps/check); the machine checks it again on save and may refuse it
// with its own reason, which the form shows.
function capForm(d, f) {
  const c = state.caps;
  const v = f.form;
  const errs = {};
  const field = (key, label, input, hint) => {
    errs[key] = el("span", { class: "hint error", role: "status" });
    input.addEventListener("input", () => { v[key] = input.value; checkSoon(); });
    return el("label", { class: "field grow" }, el("span", { class: "label" }, label), input, hint ? el("span", { class: "hint" }, hint) : null, errs[key]);
  };
  const text = (key, attrs) => el("input", { class: "input", type: "text", value: v[key], autocomplete: "off", spellcheck: "false", "data-focus": `capform:${key}`, ...attrs });
  const area = (key, placeholder) => {
    const t = el("textarea", { class: "json", spellcheck: "false", placeholder, "data-focus": `capform:${key}` });
    t.value = v[key];
    return t;
  };
  // The choices have no field of their own, but say what is wrong as well.
  errs.effect = el("span", { class: "hint error", role: "status" });
  errs.platform = el("span", { class: "hint error", role: "status" });
  const refusal = el("div", {});
  let timer = null;
  let asked = 0;
  const show = (e) => { for (const k of Object.keys(errs)) errs[k].textContent = (e && e[k]) || ""; };
  const check = async () => {
    const n = ++asked;
    const r = await api("POST", "/api/caps/check", { form: v });
    if (n === asked) show(r.errors);
  };
  function checkSoon() {
    clearTimeout(timer);
    timer = setTimeout(() => check().catch(() => {}), 300);
  }
  const effect = segmented("What it does", CAP_EFFECTS.map((e) => e[0].toUpperCase() + e.slice(1)), CAP_EFFECTS.indexOf(v.effect), (i) => { v.effect = CAP_EFFECTS[i]; checkSoon(); });
  const platform = segmented("Where it runs", ["Any system", "Linux", "Windows"], CAP_PLATFORMS.indexOf(v.platform), (i) => { v.platform = CAP_PLATFORMS[i]; checkSoon(); });
  const save = act(async () => {
    refusal.replaceChildren();
    try {
      await api("POST", "/api/caps/save", { id: d.node.id, form: v, adding: f.adding });
    } catch (e) {
      if (e.auth) throw e;
      if (e.body && e.body.errors) { show(e.body.errors); return; }
      refusal.replaceChildren(banner("error", "alert", `The machine refused: ${e.message}`));
      return;
    }
    notify(f.adding ? `Added ${v.name}.` : `Saved ${v.name}.`);
    c.form = null;
    await loadCaps();
  });
  const card = el("div", { class: "card cap-form" },
    el("div", { class: "form-row" },
      field("name", "Name (cap.action, like sensors.read)", text("name", { readonly: !f.adding })),
      field("timeout", "Time limit (seconds, empty for the machine's default)", text("timeout", { inputmode: "numeric" }))),
    el("div", { class: "form-row" }, el("div", { class: "field grow" }, el("span", { class: "label" }, "What it does"), effect,
      el("span", { class: "hint" }, "It counts as execute whatever it says, except sense and actuate, which only the machine's owner turns on."), errs.effect)),
    el("div", { class: "form-row" }, field("summary", "Summary (one line for the agent)", text("summary"))),
    el("div", { class: "form-row" }, field("command", "Command (the program first; a word {field} is the argument field)", text("command", { class: "input mono" }))),
    el("div", { class: "form-row" }, field("params", "Arguments (a JSON Schema; empty for none)", area("params", "{\"type\": \"object\", \"properties\": {}}"))),
    el("div", { class: "form-row" }, field("result", "Result (a JSON Schema the printed JSON fits; empty for the printed text)", area("result", "empty: the printed text"))),
    el("div", { class: "form-row" }, el("div", { class: "field grow" }, el("span", { class: "label" }, "Where it runs"), platform, errs.platform)),
    refusal,
    el("div", { class: "actions" },
      btn("Cancel", "ghost", () => { c.form = null; draw(true); }, null, "capform:cancel"),
      btn(f.adding ? "Add" : "Save", "primary", save, "check", "capform:save")));
  check().catch(() => {});
  return card;
}

// ---- Log ----

// The levels the page filters by, most to least verbose: a level shows itself
// and what is more severe. The log keeps the level set in Settings; this only
// narrows what is shown.
const LOG_LEVELS = [
  { value: "debug", text: "Everything" },
  { value: "info", text: "Info and above" },
  { value: "warn", text: "Warnings and errors" },
  { value: "error", text: "Errors only" },
];
const LOG_TONE = { error: "down", warn: "warn", info: "", debug: "" };
// What the page asks for. `node` is a machine's id, "-" for what is about no
// machine, null for all.
const logFilter = { level: "debug", node: null, q: "", live: true };
let logRun = 0;
let logTimer = null;
let logNodes = [];

// The boxes of the page are made once and kept: draw() leaves them in place
// when the entries change, so a search typed into the field or a list being
// used is not cut off by the next poll.
const logLevelPicker = picker({
  label: "Level", search: "Search levels", none: "No level matches.",
  onpick: (level) => { logFilter.level = level; logLevelPicker.set(LOG_LEVELS, level); logLoad(); },
});
const logNodePicker = picker({
  label: "Machine", search: "Search machines", none: "No machine matches.",
  onpick: (node) => { logFilter.node = node; logNodePicker.set(logNodes, node); logLoad(); },
});
const logSearch = el("input", { class: "input", type: "search", placeholder: "Search the messages", autocomplete: "off", spellcheck: "false" });
logSearch.addEventListener("input", () => {
  clearTimeout(logTimer);
  logTimer = setTimeout(() => { logFilter.q = logSearch.value; logLoad(); }, 250);
});
const logLiveDot = el("span", { class: "dot up" });
const logLiveText = el("span", {}, "Live");
const logLive = el("button", { type: "button", class: "btn ghost", "aria-pressed": "true", title: "Pause or resume the updates", onclick: () => setLogLive(!logFilter.live) }, logLiveDot, logLiveText);
const logDownload = el("button", { type: "button", class: "btn ghost", title: "The whole log file, one JSON object per line", onclick: act(() => download("/api/log/download", "nerve-center-log.jsonl")) }, icon("download", "sm"), "Download the file");
const logParts = {
  head: el("div"),
  bar: el("div", { class: "card log-bar" }, el("div", { class: "form-row" },
    logLevelPicker.root, logNodePicker.root,
    el("label", { class: "field" }, el("span", { class: "label" }, "Search"), logSearch),
    el("div", { class: "log-tools" }, logLive, logDownload))),
  rows: el("div"),
};

function setLogLive(on) {
  logFilter.live = on;
  logLive.setAttribute("aria-pressed", String(on));
  logLiveDot.className = "dot" + (on ? " up" : "");
  logLiveText.textContent = on ? "Live" : "Paused";
  if (on) logLoad();
}

function logPath() {
  const p = new URLSearchParams();
  if (logFilter.level !== "debug") p.set("level", logFilter.level);
  if (logFilter.node) p.set("node", logFilter.node);
  if (logFilter.q.trim()) p.set("q", logFilter.q.trim());
  const q = p.toString();
  return "/api/log" + (q ? "?" + q : "");
}

// Asks for the entries the filters want. An answer that comes after a newer
// question is dropped.
async function logLoad() {
  const run = ++logRun;
  try {
    const l = await api("GET", logPath());
    if (run !== logRun) return;
    state.log = l;
    if (current() === "log") draw(false);
  } catch (e) {
    // A center that cannot be reached is told by the poll of the overview.
    if (!e.auth && !(e instanceof TypeError)) notify(e.message, "error");
  }
}

function clock(ms) {
  const d = new Date(ms);
  const t = d.toLocaleTimeString(undefined, { hourCycle: "h23" });
  return d.toDateString() === new Date().toDateString() ? t : `${d.toLocaleDateString()} ${t}`;
}

function logRow(e) {
  return el("div", { class: "log-row " + e.level },
    el("span", { class: "log-when mono", title: when(e.ts) }, clock(e.ts)),
    pill(LOG_TONE[e.level] || "", e.level),
    e.node ? el("span", { class: "chip", title: e.node_id || "" }, e.node) : null,
    el("span", { class: "log-msg" }, e.msg));
}

// What the center did and saw, newest first, as the center kept it.
function pageLog() {
  const l = state.log;
  if (!l) return [loading()];
  const machines = l.nodes.slice().sort((a, b) => a.name.localeCompare(b.name));
  // A machine the log no longer remembers cannot be filtered by.
  if (logFilter.node !== null && logFilter.node !== "-" && !machines.some((n) => n.id === logFilter.node)) logFilter.node = null;
  logLevelPicker.set(LOG_LEVELS, logFilter.level);
  logNodes = [
    { value: null, text: "All machines" },
    { value: "-", text: "The center itself" },
    ...machines.map((n) => ({ value: n.id, text: n.paired ? n.name : `${n.name} (removed)` })),
  ];
  logNodePicker.set(logNodes, logFilter.node);
  logDownload.hidden = !l.file;
  const count = (level) => l.entries.filter((e) => e.level === level).length;
  const stats = [[l.entries.length, l.entries.length === 1 ? "entry shown" : "entries shown"]];
  if (count("error")) stats.push([count("error"), "errors", "danger"]);
  if (count("warn")) stats.push([count("warn"), count("warn") === 1 ? "warning" : "warnings", "warn"]);
  logParts.head.replaceChildren(head("log", "Log",
    `Links, pairing, changes, refused and failed calls, and errors, newest first. The center keeps the level ${l.level}; change that in Settings.`, stats));
  const filtered = logFilter.level !== "debug" || logFilter.node !== null || logFilter.q.trim() !== "";
  logParts.rows.replaceChildren(l.entries.length
    ? el("div", { class: "card log-rows" }, l.entries.map(logRow))
    : empty(filtered ? "Nothing matches these filters." : "The log is empty.", "log"));
  return [logParts.head, logParts.bar, logParts.rows];
}

// ---- Settings ----

// The levels the center can keep its log at, for the Settings page.
const SETTINGS_LEVELS = [
  { value: "error", text: "Error" },
  { value: "warn", text: "Warn" },
  { value: "info", text: "Info (the default)" },
  { value: "debug", text: "Debug" },
];

function pageSettings() {
  const s = state.settings;
  if (!s) return [loading()];
  s.tokensBox = el("div", { class: "list" });
  drawTokens();
  const name = el("input", { class: "input", type: "text", maxlength: "64", value: s.center.name, id: "c-name" });
  const days = el("input", { class: "input num", type: "number", min: "1", max: "366", value: s.center.retention_days, id: "c-days" });
  const pairMinutes = el("input", { class: "input num", type: "number", min: "1", max: "1440", value: s.center.pair_code_minutes, id: "c-pair-minutes" });
  let logLevel = s.center.log_level;
  const levelPicker = picker({
    label: "Log level", search: "Search levels", none: "No level matches.",
    onpick: (level) => { logLevel = level; levelPicker.set(SETTINGS_LEVELS, level); },
  });
  levelPicker.set(SETTINGS_LEVELS, logLevel);
  return [
    head("settings", "Settings", "The center, the tokens harnesses use, and each machine's own settings."),
    section("Center", null, null, el("div", { class: "card" },
      el("div", { class: "form-row" },
        el("label", { class: "field" }, el("span", { class: "label" }, "Name"), name),
        el("label", { class: "field" }, el("span", { class: "label" }, "Keep statistics for (days)"), days),
        el("label", { class: "field" }, el("span", { class: "label" }, "Pairing code valid for (minutes, at most 1440)"), pairMinutes)),
      el("div", { class: "form-row" }, levelPicker.root),
      el("p", { class: "meta" }, "Debug adds detail for tracking down a problem and makes the log file grow faster. What the log holds is on the Log page."),
      s.center.log_level_pinned ? el("p", { class: "meta" }, `The --log option (NERVE_CENTER_LOG) sets the level at every start and wins over this setting. This run keeps the level ${s.center.log_level_now}.`) : null,
      el("div", { class: "actions" }, el("button", { type: "button", class: "btn primary", "data-focus": "center:save", onclick: act(async () => {
        await api("POST", "/api/center", { name: name.value, retention_days: Number(days.value), pair_code_minutes: Number(pairMinutes.value), log_level: logLevel });
        notify("Saved.");
      }) }, "Save")))),
    section("Center key", "Machines check the center by this key's pin. Rotating it makes a new key; the old one is served for 7 more days, so the machines learn the new one when they link.", null,
      centerKey(s.center.key)),
    section("Harness tokens", "A token lets an AI harness call this center over HTTP. It does not log in here: this page asks for the owner token.", null,
      el("div", { class: "stack" }, el("div", { class: "card" }, tokenForm()), s.tokensBox)),
    section("Machines", "Settings kept on each machine itself.", null,
      s.nodes.length ? el("div", { class: "stack" }, s.nodes.map(nodeSettings)) : empty("No machines yet.", "server")),
  ];
}

// The center's TLS key (docs/user/center.md#rotate-the-key). The new pin is
// shown once, when the rotation is made, as a pairing shows its code.
function centerKey(k) {
  const rotate = act(async () => {
    const yes = await modal({ title: "Rotate the center's key?", message: "Machines that link in the next 7 days follow it. A machine away longer, or one older than this center, has to be paired again.", confirm: "Rotate" });
    if (!yes) return;
    const r = await api("POST", "/api/center/key/rotate");
    state.newPin = r.pin;
    notify(`The key was rotated; ${plural(r.told, "machine")} linked now ${r.told === 1 ? "was" : "were"} told.`);
    await loadSettings();
  });
  const finish = act(async () => {
    const yes = await modal({ title: "Serve the new key now?", message: "Machines that were not told of the rotation cannot link any more and have to be paired again.", confirm: "Serve it now", danger: true });
    if (!yes) return;
    await api("POST", "/api/center/key/finish");
    notify("The center serves its new key now.");
    await loadSettings();
  });
  return el("div", { class: "card" },
    state.newPin ? el("div", { class: "banner ok" }, icon("key"),
      el("span", {}, "New pin, shown once: ", el("code", { class: "mono" }, state.newPin)),
      el("button", { type: "button", class: "btn ghost sm", onclick: () => copy(state.newPin) }, icon("copy", "sm"), "Copy"),
      el("button", { type: "button", class: "btn ghost sm", "aria-label": "Hide", onclick: () => { state.newPin = null; draw(true); } }, icon("x", "sm"))) : null,
    el("p", { class: "meta" }, "Pin served now: ", el("code", { class: "mono" }, k.pin)),
    k.grace_until_ms ? el("p", { class: "meta" }, `A rotation is in its grace: the old key is served until ${when(k.grace_until_ms)}.`) : null,
    el("div", { class: "actions" }, k.grace_until_ms
      ? btn("Serve the new key now", "danger-soft", finish, "key", "key:finish")
      : btn("Rotate key", "", rotate, "key", "key:rotate")));
}

function tokenForm() {
  const label = el("input", { class: "input", type: "text", placeholder: "Label, for example the harness name", "aria-label": "Token label", maxlength: "64" });
  return el("div", { class: "form-row" }, el("label", { class: "field" }, el("span", { class: "label" }, "New token"), label),
    el("button", { type: "button", class: "btn primary", "data-focus": "token:create", onclick: act(async () => {
      const r = await api("POST", "/api/tokens/create", { label: label.value });
      label.value = "";
      state.newToken = r.token;
      await loadTokens();
    }) }, icon("key", "sm"), "Create"));
}

async function loadTokens() {
  state.settings.tokens = await api("GET", "/api/tokens");
  drawTokens();
}

function drawTokens() {
  const s = state.settings;
  s.tokensBox.replaceChildren(...[
    state.newToken ? el("div", { class: "banner ok" }, icon("key"),
      el("span", {}, "New token, shown once: ", el("code", { class: "mono" }, state.newToken)),
      el("button", { type: "button", class: "btn ghost sm", onclick: () => copy(state.newToken) }, icon("copy", "sm"), "Copy"),
      el("button", { type: "button", class: "btn ghost sm", "aria-label": "Hide", onclick: () => { state.newToken = null; drawTokens(); } }, icon("x", "sm"))) : null,
    s.tokens.length ? s.tokens.map((t) => t.settings
      // The token of the settings (NERVE_CENTER_HARNESS_TOKEN or --harness-token):
      // only a change of the settings and a restart remove it.
      ? el("div", { class: "card" }, el("div", { class: "card-top" },
        icon("key"), el("span", { class: "name mono" }, t.label), el("span", { class: "meta push" }, "From the center's settings; remove it there")))
      : el("div", { class: "card" }, el("div", { class: "card-top" },
        icon("key"), el("span", { class: "name" }, t.label || "(no label)"), el("span", { class: "meta push" }, `Created ${ago(t.created_ms)}`),
        btn("Delete", "danger-soft", act(async () => { await api("POST", "/api/tokens/delete", { id: t.id }); await loadTokens(); }), "trash", `token:${t.id}:delete`))))
      : el("p", { class: "meta" }, "No tokens yet.")].flat().filter(Boolean));
}

// The sudo password is sealed here, in the browser, for a one-shot offer the
// machine signed (docs/dev/spec/protocol.md §7.4.1): X25519, HKDF-SHA256, AES-256-GCM.
// The center relays the sealed box and cannot open it.
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function sealSudo(offer, password) {
  const enc = new TextEncoder();
  const subtle = crypto.subtle;
  const mine = await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const theirs = await subtle.importKey("raw", unb64(offer.key), { name: "X25519" }, false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: theirs }, mine.privateKey, 256);
  const hkdf = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("nerve-sudo-v1"), info: enc.encode(offer.offer) },
    hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ password, offer: offer.offer, ts: Date.now() }));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(offer.offer) }, key, plain);
  const pub = await subtle.exportKey("raw", mine.publicKey);
  return { offer: offer.offer, key: b64(pub), iv: b64(iv), ct: b64(ct) };
}

// The machine's sudo switch: on only with a password its `sudo -v` accepts.
function sudoSwitch(n) {
  const label = el("span", { class: "meta" }, "Sudo: …");
  const pw = el("input", { type: "password", class: "input", autocomplete: "off", placeholder: "sudo password", "aria-label": `Sudo password of ${n.name}` });
  const show = (on) => { label.textContent = on === "on" ? "Sudo: on" : "Sudo: off"; };
  const on = btn("Turn sudo on", "", act(async () => {
    const password = pw.value;
    pw.value = "";
    if (!password) { notify("Enter the machine's sudo password first.", "error"); return; }
    const offer = await api("POST", "/api/nodes/sudo/offer", { id: n.id });
    const sealed = await sealSudo(offer, password);
    const r = await api("POST", "/api/nodes/sudo", { id: n.id, on: true, sealed });
    show(r.sudo);
    notify(`Sudo is on for ${n.name}: sudo commands on the sudo allow list run.`);
  }));
  const off = btn("Turn sudo off", "", act(async () => {
    const r = await api("POST", "/api/nodes/sudo", { id: n.id, on: false });
    show(r.sudo);
    notify(`Sudo is off for ${n.name}.`);
  }));
  return { show, row: el("div", { class: "actions" }, label, pw, on, off) };
}

// A machine's own settings are fetched when its card is opened, so the page
// does not ask every machine up front.
function nodeSettings(n) {
  const body = el("div", { class: "body" });
  const card = el("details", { class: "card" },
    el("summary", {}, el("span", { class: "dot" + (n.online ? " up" : "") }), el("span", { class: "name" }, n.name),
      pill(n.online ? "up" : "down", n.online ? "online" : "offline"), icon("chev", "sm chev")),
    body);
  if (!n.settings_write) {
    body.append(el("p", { class: "meta" }, "This machine keeps its settings to itself (settings grant off). Change them with nerve-node on the machine."));
    return card;
  }
  if (!n.online) {
    body.append(el("p", { class: "meta" }, "Offline; its settings can be changed when it is back."));
    return card;
  }
  const area = el("textarea", { class: "json", spellcheck: "false", "aria-label": `Settings of ${n.name}` });
  const msg = el("p", { class: "meta" });
  const sudo = sudoSwitch(n);
  let version = null;
  const load = async () => {
    const s = await api("GET", `/api/nodes/settings?id=${encodeURIComponent(n.id)}`);
    area.value = JSON.stringify(s.document, null, 2);
    version = s.version;
    msg.textContent = `Version ${version}.`;
    sudo.show(s.sudo);
  };
  body.append(sudo.row, area, msg, el("div", { class: "actions" },
    btn("Reload", "", act(load), "refresh"),
    btn("Save", "primary", act(async () => {
      let doc;
      try { doc = JSON.parse(area.value); } catch (e) { msg.textContent = `Not valid JSON: ${e.message}`; return; }
      try {
        const r = await api("POST", "/api/nodes/settings", { id: n.id, document: doc, if_version: version });
        version = r.version;
        msg.textContent = `Saved, version ${version}.`;
        notify(`Saved the settings of ${n.name}.`);
      } catch (e) { if (e.auth) throw e; msg.textContent = `The machine refused: ${e.message}`; }
    }))));
  card.addEventListener("toggle", () => {
    if (card.open && version === null) load().catch((e) => { msg.textContent = e.message; });
  });
  return card;
}

async function loadSettings() {
  const run = ++settingsRun;
  try {
    const [center, tokens, overview] = await Promise.all([api("GET", "/api/center"), api("GET", "/api/tokens"), api("GET", "/api/overview")]);
    if (run !== settingsRun) return;
    state.settings = { center, tokens, nodes: overview.nodes, tokensBox: null };
    if (current() === "settings") draw(true);
  } catch (e) {
    if (!e.auth) notify(e.message, "error");
  }
}

// ---- Drawing and polling ----

function current() {
  const h = location.hash.slice(1);
  return PAGES[h] ? h : "overview";
}

function signature(page) {
  const minute = Math.floor(Date.now() / 60000);
  return JSON.stringify([page, state.overview, page === "stats" ? state.stats : page === "audit" ? state.audit : page === "log" ? state.log : page === "help" ? !!state.help : null, state.pairing, minute]);
}

function draw(force) {
  const page = current();
  if (page === "settings" || page === "checker" || page === "capabilities") {
    if (force) {
      replacePage(PAGES[page].view().flat().filter((p) => p != null));
      // A page drawn while a save runs (the user came back to it) has its
      // controls off as well.
      if (page === "checker" && checkerSaving) lockSaves(true);
    }
    return;
  }
  const sig = signature(page);
  if (!force && sig === lastSig) return;
  lastSig = sig;
  // A part a page leaves out is null; it is not drawn as the word.
  const parts = PAGES[page].view().flat().filter((p) => p != null);
  // A page that keeps its parts between redraws (the statistics picker) has
  // updated them in place: moving them would take the focus off the picker.
  const shown = Array.from($("page").children);
  if (parts.length === shown.length && parts.every((p, i) => p === shown[i])) return;
  replacePage(parts);
}

// The pairing card shows a one-time code. Once the center no longer has it
// open, a machine used it (or it ran out of tries), and the card has done its
// job: close it, so nobody thinks the pairing failed and tries again. The
// center says which machine the code paired, so the page never guesses it from
// the machine list, which may be older than the pairing. A pairing that is
// still under way counts as open there.
async function closePairingWhenUsed() {
  const p = state.pairing;
  if (!p) return;
  const { open, node } = await api("POST", "/api/pair/status", { code: p.code });
  if (open || state.pairing !== p) return;
  state.pairing = null;
  if (node) notify(`Paired ${node.name}.`);
  else notify("The pairing code is no longer valid.", "error");
}

async function tick() {
  if (busy || !session) return;
  busy = true;
  try {
    const page = current();
    const jobs = [api("GET", "/api/overview")];
    if (page === "stats") jobs.push(api("GET", "/api/stats"));
    if (page === "audit") jobs.push(api("GET", "/api/audit"));
    // The command list does not change while the center runs: ask once.
    if (page === "help" && !state.help) jobs.push(api("GET", "/api/help"));
    const [o, extra] = await Promise.all(jobs);
    state.overview = o;
    if (page === "stats") state.stats = extra;
    if (page === "audit") state.audit = extra;
    if (page === "help" && extra) state.help = extra;
    await closePairingWhenUsed();
    if (down) notify("Connected to the center again.");
    down = false;
    draw(false);
    // The log asks for itself, so that a filter changed meanwhile is not
    // answered with the old filter's entries.
    if (page === "log" && logFilter.live) logLoad();
    // The Action checker page refreshes the local model's status in place.
    if (page === "checker") pollCheckerLocal().catch(() => {});
  } catch (e) {
    if (!e.auth && !down) notify("Cannot reach the center. Trying again.", "error");
    down = !e.auth;
  } finally {
    busy = false;
  }
}

// ---- Shell: navigation, drawer, theme ----

function setNav(open) {
  $("shell").dataset.nav = open ? "open" : "";
  $("nav-open").setAttribute("aria-expanded", String(open));
  if (open) $("nav-close").focus();
}

function go() {
  const page = current();
  statsPicker.close();
  capsPicker.close();
  logLevelPicker.close();
  logNodePicker.close();
  for (const a of document.querySelectorAll("[data-page]")) {
    if (a.dataset.page === page) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  $("top-title").textContent = PAGES[page].title;
  setNav(false);
  state.newToken = null;
  lastSig = null;
  // A save in flight holds the focus for its control on the page it started
  // on, not on the one the user went to.
  pendingFocus = null;
  if (page === "log" && !logFilter.live) setLogLive(true);
  const p = $("page");
  p.classList.remove("enter");
  void p.offsetWidth;
  p.classList.add("enter");
  $("scroll").scrollTop = 0;
  if (page === "settings") {
    state.settings = null;
    draw(true);
    loadSettings();
  } else if (page === "checker") {
    state.checker = null;
    checkerPick = null;
    draw(true);
    loadChecker().catch((e) => { if (!e.auth) notify(e.message, "error"); });
  } else if (page === "capabilities") {
    state.caps = null;
    draw(true);
    loadCaps().catch((e) => { if (!e.auth) notify(e.message, "error"); });
  } else {
    draw(true);
  }
  tick();
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
    const s = await startSession();
    if (!s) return;
    $("signout").hidden = !s.login;
  } catch (_) {
    return $("page").replaceChildren(banner("", "alert", "Cannot reach the center. Reload to try again."));
  }
  go();
  setInterval(() => { if (!document.hidden) tick(); }, 2000);
}

start();

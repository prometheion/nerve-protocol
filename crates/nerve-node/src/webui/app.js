// The Nerve node web UI. Plain JavaScript, no build step: the node serves
// this file as is, after the shared kit.js. Everything shown comes from
// /api, asked with this tab's session; every change is one command of the
// CLI that the node runs for its owner. The page asks the node every two
// seconds and draws again only when the answer changed.
"use strict";

const PAGES = {
  overview: { title: "Overview", view: pageOverview },
  settings: { title: "Settings", view: pageSettings },
};

let lastSig = null;
let busy = false;
let down = false;
const state = { overview: null, ui: null };

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

// ---- Settings ----

function pageSettings() {
  const s = state.ui;
  if (!s) return [loading()];
  return [
    head("settings", "Settings", "The node's settings."),
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
  const sig = JSON.stringify([page, state.overview, page === "settings" ? state.ui : null, Math.floor(Date.now() / 60000)]);
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
    const [o, extra] = await Promise.all(jobs);
    state.overview = o;
    if (page === "settings") state.ui = extra;
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
    if (!(await startSession())) return;
  } catch (_) {
    return $("page").replaceChildren(banner("", "alert", "Cannot reach the node. Reload to try again."));
  }
  go();
  setInterval(() => { if (!document.hidden) tick(); }, 2000);
}

start();

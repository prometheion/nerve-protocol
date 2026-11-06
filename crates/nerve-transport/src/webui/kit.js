// The parts the web UIs of the center and the node share: icons, elements,
// the API call with the session header, toasts, dialogs, the focus that a
// page drawn anew keeps, page building blocks, Help and the theme. Plain
// JavaScript, no build step, loaded before each UI's app.js; the functions
// it calls back (current, tick, draw) are that app's.
"use strict";

// Lucide icons (ISC licence), inner markup only; icon() wraps them in an svg.
const ICONS = {
  overview: "<rect width=\"7\" height=\"9\" x=\"3\" y=\"3\" rx=\"1\"/><rect width=\"7\" height=\"5\" x=\"14\" y=\"3\" rx=\"1\"/><rect width=\"7\" height=\"9\" x=\"14\" y=\"12\" rx=\"1\"/><rect width=\"7\" height=\"5\" x=\"3\" y=\"16\" rx=\"1\"/>",
  stats: "<path d=\"M3 3v16a2 2 0 0 0 2 2h16\"/><path d=\"M18 17V9\"/><path d=\"M13 17V5\"/><path d=\"M8 17v-3\"/>",
  audit: "<path d=\"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z\"/><path d=\"m9 12 2 2 4-4\"/>",
  settings: "<path d=\"M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/>",
  menu: "<line x1=\"4\" x2=\"20\" y1=\"12\" y2=\"12\"/><line x1=\"4\" x2=\"20\" y1=\"6\" y2=\"6\"/><line x1=\"4\" x2=\"20\" y1=\"18\" y2=\"18\"/>",
  x: "<path d=\"M18 6 6 18\"/><path d=\"m6 6 12 12\"/>",
  plus: "<path d=\"M5 12h14\"/><path d=\"M12 5v14\"/>",
  trash: "<path d=\"M3 6h18\"/><path d=\"M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6\"/><path d=\"M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2\"/><line x1=\"10\" x2=\"10\" y1=\"11\" y2=\"17\"/><line x1=\"14\" x2=\"14\" y1=\"11\" y2=\"17\"/>",
  sun: "<circle cx=\"12\" cy=\"12\" r=\"4\"/><path d=\"M12 2v2\"/><path d=\"M12 20v2\"/><path d=\"m4.93 4.93 1.41 1.41\"/><path d=\"m17.66 17.66 1.41 1.41\"/><path d=\"M2 12h2\"/><path d=\"M20 12h2\"/><path d=\"m6.34 17.66-1.41 1.41\"/><path d=\"m19.07 4.93-1.41 1.41\"/>",
  moon: "<path d=\"M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z\"/>",
  monitor: "<rect width=\"20\" height=\"14\" x=\"2\" y=\"3\" rx=\"2\"/><line x1=\"8\" x2=\"16\" y1=\"21\" y2=\"21\"/><line x1=\"12\" x2=\"12\" y1=\"17\" y2=\"21\"/>",
  logout: "<path d=\"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4\"/><polyline points=\"16 17 21 12 16 7\"/><line x1=\"21\" x2=\"9\" y1=\"12\" y2=\"12\"/>",
  copy: "<rect width=\"14\" height=\"14\" x=\"8\" y=\"8\" rx=\"2\" ry=\"2\"/><path d=\"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2\"/>",
  check: "<path d=\"M20 6 9 17l-5-5\"/>",
  alert: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><line x1=\"12\" x2=\"12\" y1=\"8\" y2=\"12\"/><line x1=\"12\" x2=\"12.01\" y1=\"16\" y2=\"16\"/>",
  refresh: "<path d=\"M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8\"/><path d=\"M21 3v5h-5\"/><path d=\"M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16\"/><path d=\"M8 16H3v5\"/>",
  key: "<path d=\"M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z\"/><circle cx=\"16.5\" cy=\"7.5\" r=\".5\" fill=\"currentColor\"/>",
  edit: "<path d=\"M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z\"/><path d=\"m15 5 4 4\"/>",
  link: "<path d=\"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71\"/><path d=\"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71\"/>",
  lock: "<rect width=\"18\" height=\"11\" x=\"3\" y=\"11\" rx=\"2\" ry=\"2\"/><path d=\"M7 11V7a5 5 0 0 1 10 0v4\"/>",
  ban: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"m4.9 4.9 14.2 14.2\"/>",
  ok: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"m9 12 2 2 4-4\"/>",
  wait: "<path d=\"M5 22h14\"/><path d=\"M5 2h14\"/><path d=\"M17 22v-4.172a2 2 0 0 0-.586-1.414L12 12l-4.414 4.414A2 2 0 0 0 7 17.828V22\"/><path d=\"M7 2v4.172a2 2 0 0 0 .586 1.414L12 12l4.414-4.414A2 2 0 0 0 17 6.172V2\"/>",
  plug: "<path d=\"M12 22v-5\"/><path d=\"M9 8V2\"/><path d=\"M15 8V2\"/><path d=\"M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z\"/>",
  info: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M12 16v-4\"/><path d=\"M12 8h.01\"/>",
  chev: "<path d=\"m6 9 6 6 6-6\"/>",
  help: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3\"/><path d=\"M12 17h.01\"/>",
  log: "<path d=\"M15 12h-5\"/><path d=\"M15 8h-5\"/><path d=\"M19 17V5a2 2 0 0 0-2-2H4\"/><path d=\"M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3\"/>",
  download: "<path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\"/><polyline points=\"7 10 12 15 17 10\"/><line x1=\"12\" x2=\"12\" y1=\"15\" y2=\"3\"/>",
  shield: "<path d=\"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z\"/>",
  bot: "<path d=\"M12 8V4H8\"/><rect width=\"16\" height=\"12\" x=\"4\" y=\"8\" rx=\"2\"/><path d=\"M2 14h2\"/><path d=\"M20 14h2\"/><path d=\"M15 13v2\"/><path d=\"M9 13v2\"/>",
  server: "<rect width=\"20\" height=\"8\" x=\"2\" y=\"2\" rx=\"2\" ry=\"2\"/><rect width=\"20\" height=\"8\" x=\"2\" y=\"14\" rx=\"2\" ry=\"2\"/><line x1=\"6\" x2=\"6.01\" y1=\"6\" y2=\"6\"/><line x1=\"6\" x2=\"6.01\" y1=\"18\" y2=\"18\"/>",
  keyboard: "<path d=\"M10 8h.01\"/><path d=\"M12 12h.01\"/><path d=\"M14 8h.01\"/><path d=\"M16 12h.01\"/><path d=\"M18 8h.01\"/><path d=\"M6 8h.01\"/><path d=\"M7 16h10\"/><path d=\"M8 12h.01\"/><rect width=\"20\" height=\"16\" x=\"2\" y=\"4\" rx=\"2\"/>",
  terminal: "<polyline points=\"4 17 10 11 4 5\"/><line x1=\"12\" x2=\"20\" y1=\"19\" y2=\"19\"/>",
  external: "<path d=\"M15 3h6v6\"/><path d=\"M10 14 21 3\"/><path d=\"M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6\"/>"
};

const SVG = "http://www.w3.org/2000/svg";

// The session token the login answered, kept in sessionStorage: it goes as
// a header with every API call, never as a cookie, so no other page or port
// of this browser's host gets it.
const SESSION_KEY = "nerve.session";
let session = null;

const $ = (id) => document.getElementById(id);

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    e.append(typeof k === "string" || typeof k === "number" ? document.createTextNode(String(k)) : k);
  }
  return e;
}

function icon(name, cls) {
  const s = document.createElementNS(SVG, "svg");
  s.setAttribute("class", "ico" + (cls ? " " + cls : ""));
  fillIcon(s, name);
  return s;
}

function fillIcon(s, name) {
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("aria-hidden", "true");
  s.innerHTML = ICONS[name] || "";
}

for (const s of document.querySelectorAll("svg[data-icon]")) fillIcon(s, s.dataset.icon);

// ---- Session ----

// This tab's session, as sessionStorage keeps it: a new tab, or storage that
// is blocked, logs in again.
function storedSession() {
  try { return sessionStorage.getItem(SESSION_KEY); } catch (_) { return null; }
}

function keepSession(s) {
  try {
    if (s) sessionStorage.setItem(SESSION_KEY, s);
    else sessionStorage.removeItem(SESSION_KEY);
  } catch (_) { /* storage blocked: this page holds it until it is left */ }
}

// Asks the server whether this tab is signed in: its answer, or null when
// the page goes to the login. A UI without a login hands out a session here.
async function startSession() {
  session = storedSession();
  const r = await fetch("/api/session", { headers: session ? { "X-Nerve-Session": session } : {} });
  let s = {};
  try { s = await r.json(); } catch (_) { /* no JSON: not signed in */ }
  if (s.session) { session = s.session; keepSession(session); }
  if (!r.ok || !s.logged_in) {
    keepSession(null);
    location.replace("/login");
    return null;
  }
  return s;
}

// Signs out: the server ends the session and this tab forgets it.
async function signOut() {
  try {
    await fetch("/logout", { method: "POST", headers: { "X-Nerve-Session": session || "" } });
  } catch (_) { /* the server is gone: its sessions went with it */ }
  keepSession(null);
  session = null;
  location.assign("/login");
}

async function api(method, path, body) {
  const opts = { method, headers: { "X-Nerve-Session": session || "" } };
  if (method === "POST") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body || {});
  }
  const r = await fetch(path, opts);
  let v = {};
  try { v = await r.json(); } catch (_) { /* empty body */ }
  if (r.status === 401) {
    keepSession(null);
    location.assign("/login");
    const err = new Error("Your session ended. Sign in again.");
    err.auth = true;
    throw err;
  }
  if (!r.ok) {
    const why = v.data && v.data.field ? ` (${v.data.field})` : "";
    const err = new Error((v.error || r.statusText) + (v.code ? ` [${v.code}]` : "") + why);
    // A form shows what the answer says of each field.
    err.body = v;
    err.status = r.status;
    throw err;
  }
  return v;
}

// A file the server sends, saved by the browser: the session goes as a
// header, which a plain link cannot send.
async function download(path, name) {
  const r = await fetch(path, { headers: { "X-Nerve-Session": session || "" } });
  if (r.status === 401) {
    keepSession(null);
    location.assign("/login");
    return;
  }
  if (!r.ok) {
    let v = {};
    try { v = await r.json(); } catch (_) { /* no JSON */ }
    throw new Error(v.error || r.statusText);
  }
  const url = URL.createObjectURL(await r.blob());
  const a = el("a", { href: url, download: name, hidden: true });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---- Formatting ----

function when(ms) {
  return ms ? new Date(ms).toLocaleString() : "never";
}

function ago(ms) {
  if (!ms) return "never";
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

function duration(ms) {
  const m = Math.round(ms / 60000);
  if (ms < 60000) return `${Math.round(ms / 1000)} s`;
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  return h < 48 ? `${h} h ${m % 60} min` : `${Math.floor(h / 24)} d ${h % 24} h`;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many || one + "s"}`;
}

// ---- Feedback: toasts and dialogs ----

// A short note in the corner: it rises in, and fades out when its time is up.
function notify(text, kind) {
  const box = $("toasts");
  const t = el("div", { class: "toast " + (kind || "ok") }, icon(kind === "error" ? "alert" : "check"), el("span", {}, text));
  box.append(t);
  while (box.children.length > 4) box.firstChild.remove();
  setTimeout(() => {
    t.classList.add("leaving");
    setTimeout(() => t.remove(), 150);
  }, kind === "error" ? 7000 : 3500);
}

// One modal: a title, an optional message and text field, Cancel and a
// confirm button. Resolves with the field text (or true), null when cancelled.
function modal(o) {
  return new Promise((resolve) => {
    const d = $("dlg");
    const input = o.field
      ? el("input", { class: "input", type: "text", value: o.field.value || "", required: true, pattern: o.field.pattern, autocomplete: "off", spellcheck: "false" })
      : null;
    let ok = false;
    const form = el("form", { method: "dialog", onsubmit: () => { ok = true; } },
      el("div", { class: "dlg-head" },
        el("h2", {}, o.title),
        el("button", { type: "button", class: "btn ghost icon sm", "aria-label": "Close", onclick: () => d.close() }, icon("x"))),
      o.message ? el("p", { class: "msg" }, o.message) : null,
      input ? el("label", { class: "field" }, el("span", { class: "label" }, o.field.label), input) : null,
      el("div", { class: "foot" },
        el("button", { type: "button", class: "btn ghost", onclick: () => d.close() }, "Cancel"),
        el("button", { type: "submit", class: "btn " + (o.danger ? "danger" : "primary") }, o.confirm)));
    // The button that asked waits for the answer without a spinner, and
    // is busy again once the answer is yes.
    const asking = Array.from(document.querySelectorAll('.btn[aria-busy="true"]'));
    for (const b of asking) { setBusy(b, false); b.disabled = true; }
    d.addEventListener("close", () => {
      if (ok) for (const b of asking) setBusy(b, true);
      resolve(ok ? (input ? input.value : true) : null);
    }, { once: true });
    d.replaceChildren(form);
    d.showModal();
    if (input) { input.focus(); input.select(); }
  });
}

// A busy button waits for what it started: a spinner in place of its icon,
// or over its text when it has none, and no click.
function setBusy(b, on) {
  b.disabled = on;
  // A switch that saves is only off while it does.
  if (b.tagName !== "BUTTON") return;
  if (!on) {
    b.removeAttribute("aria-busy");
    b.classList.remove("bare");
    for (const s of b.querySelectorAll(":scope > .spinner")) s.remove();
    return;
  }
  b.setAttribute("aria-busy", "true");
  b.classList.toggle("bare", !b.querySelector(":scope > .ico"));
  b.prepend(el("span", { class: "spinner", "aria-hidden": "true" }));
}

// Runs a button action: busy while it works, errors become a toast, and
// the page is asked again afterwards.
function act(fn) {
  return async (ev) => {
    const b = ev.currentTarget;
    // A busy control may lose the focus, and a page that is drawn anew
    // loses it for good: the page puts it back where it was.
    const spot = focusSpot(b);
    pendingFocus = spot;
    setBusy(b, true);
    try { await fn(ev); await tick(); draw(false); }
    catch (e) { if (!e.auth) notify(e.message, "error"); }
    finally { setBusy(b, false); if (pendingFocus === spot) pendingFocus = null; }
  };
}

// The control the keyboard focus is on, named by what it is for and not by
// where it sits: a list that gains or loses an item moves its controls, and
// a position would name the End, Remove or Disable of another item, which
// Enter then acts on. A control with a stable `data-focus` key (its kind,
// the item's id and what it does) gets the focus back in a page drawn anew
// (a save redraws the whole page, the poll redraws a list); a control
// without one does not. When the key is gone (the item was ended, removed)
// or was not unique when the focus was taken or is not now, the focus goes
// to the heading of the section the control was in, which does nothing on
// Enter. A text field that gets the focus back gets what was typed into it
// back too: the redraw builds the field anew, and the user would type on
// into an empty one.
let pendingFocus = null;

function focusSpot(node) {
  const page = $("page");
  if (!node || node === page || !page.contains(node)) return null;
  const sec = node.closest("section[data-focus]");
  // A key the page holds twice names no one control: when one of the two is
  // gone the other would be unique and take the focus, and Enter would act
  // on an item the user never picked. Such a control counts as one without a
  // key, so the focus falls back to its section's heading.
  const key = node.dataset.focus && focusTarget(node.dataset.focus) ? node.dataset.focus : null;
  // What a text field holds is read now, from the old page: the new field is
  // drawn from the saved state and has lost it.
  const text = isTextField(node)
    ? { value: node.value, start: node.selectionStart, end: node.selectionEnd } : null;
  return { node, key, section: sec ? sec.dataset.focus : null, page: current(), text };
}

function isTextField(e) {
  return e.tagName === "TEXTAREA" || (e.tagName === "INPUT" && !["checkbox", "radio", "button", "submit"].includes(e.type));
}

// The one element of the page that has this key.
function focusTarget(key) {
  const found = Array.from($("page").querySelectorAll("[data-focus]")).filter((e) => e.dataset.focus === key);
  return found.length === 1 ? found[0] : null;
}

function restoreFocus(spot) {
  if (!spot) return;
  const page = $("page");
  const focus = (e) => { if (e && !e.disabled) e.focus({ preventScroll: true }); };
  // The very same element, put back by a page that keeps its parts.
  if (page.contains(spot.node)) return focus(spot.node);
  // A control without a usable key finds no element here and goes to the
  // heading like one whose key is gone.
  const same = spot.key && focusTarget(spot.key);
  if (same) {
    // Only the field that had the focus is carried over (a field the page
    // clears on purpose, after Add, is not the one with the focus), and only
    // into a field of the same kind.
    const t = spot.text;
    if (t && isTextField(same) && same.tagName === spot.node.tagName && same.type === spot.node.type && same.value !== t.value) {
      same.value = t.value;
      try { same.setSelectionRange(t.start, t.end); } catch (_) { /* a number field has no selection */ }
    }
    return focus(same);
  }
  const sec = spot.section && focusTarget(spot.section);
  const heading = sec && sec.querySelector("h3");
  if (heading) focus(heading);
}

// Draws a page's parts in place of what is shown, and keeps the focus where
// it is. A save that is still running holds the focus for the control that
// started it only while the focus is still on that control (or has fallen
// to the page because the control was replaced or disabled), and only on
// the page it started on; the user's own move wins.
function replacePage(parts) {
  const page = $("page");
  const active = document.activeElement;
  const p = pendingFocus;
  const held = p && p.page === current() && (active === p.node || !active || active === document.body);
  const spot = held ? p : focusSpot(active);
  page.replaceChildren(...parts);
  restoreFocus(spot);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    notify("Copied.");
  } catch (_) {
    notify("Copying is blocked here. Select the text and copy it by hand.", "error");
  }
}

// ---- Page building blocks ----

// A page's head, as the app's: its icon in a soft tile, its title, a word on
// what it is for, its numbers, and its buttons at the right.
function head(ic, title, sub, stats, actions) {
  return el("section", { class: "page-head" },
    el("div", { class: "tile" }, icon(ic, "lg")),
    el("div", { class: "head-text" },
      el("h2", {}, title),
      sub ? el("p", {}, sub) : null,
      stats ? el("div", { class: "stats-row" }, stats.map(([n, label, tone]) =>
        el("div", { class: "stat" }, el("b", { class: tone ? "tone-" + tone : "" }, n), el("span", {}, label)))) : null),
    actions ? el("div", { class: "head-actions" }, actions) : null);
}

// The heading can take the focus (but is not a stop for Tab): it is where
// the focus goes when the control it was on is gone.
function section(title, sub, action, ...kids) {
  return el("section", { class: "sec", "data-focus": `section:${title}` },
    el("div", { class: "sec-head" }, el("div", {}, el("h3", { tabindex: "-1", "data-focus": `heading:${title}` }, title), sub ? el("p", {}, sub) : null), action),
    kids);
}

// What a place shows when it has nothing to show: an icon in a soft circle
// and why.
function empty(text, ic) {
  return el("div", { class: "empty" }, el("div", { class: "empty-icon" }, icon(ic || "info")), el("p", {}, text));
}

// A page that waits for the center: three dots that pulse.
function loading() {
  return el("div", { class: "loading", role: "status" },
    el("div", { class: "dots", "aria-hidden": "true" }, el("span"), el("span"), el("span")), "Loading…");
}

// The icon of a row or a card in a soft square of its tone.
function itile(ic, tone) {
  return el("span", { class: "itile " + (tone || "") }, icon(ic));
}

function banner(kind, ic, text) {
  return el("div", { class: "banner " + kind }, icon(ic), el("span", {}, text));
}

function pill(kind, text) {
  return el("span", { class: "pill " + kind }, text);
}

// `key` names the button for the focus (see focusSpot): kind, item and what
// it does.
function btn(label, kind, onclick, ic, key) {
  return el("button", { type: "button", class: "btn sm " + (kind || ""), onclick, "data-focus": key }, ic ? icon(ic, "sm") : null, label);
}

// ---- Help ----

// Help, as the desktop app has it: the keys of this page, and the reference
// of the node's commands by topic or from A to Z, to filter, each one opening
// on what it does, how it is written and its arguments. The commands come as
// the node's own CLI definition lists them: the center sends that list
// (/api/help), nothing here names a command. Every part opens and closes on
// its own. The page is built once and kept, so the poll neither takes the
// focus off the filter nor closes what is open.
const HELP_KEYS = [
  ["Tab, Shift+Tab", "The next or the last control"],
  ["Enter, Space", "Press a button, open or close a part"],
  ["Esc", "Close a dialog, a list or the menu"],
  ["↓ ↑", "Open a list and move through it"],
  ["Page Down, Page Up", "Six entries further in a list"],
  ["Enter", "Pick the marked entry of a list"],
  ["← →", "Choose in a row of choices"],
];
// The user guide of this release (NERVE_GUIDE_REF comes before this file).
const GUIDE = `https://github.com/prometheion/nerve-protocol/tree/${NERVE_GUIDE_REF}/docs/user`;

// The folds that are open, by key, so a redraw of the page keeps them so.
const openFolds = new Set();

// The rest of a short text, folded under `summary` ("More" when empty): the
// line before it says what counts, a limit included; this holds the why and
// the detail. `key` names it across redraws.
function more(key, summary, ...body) {
  const d = el("details", { class: "more", "data-focus": `more:${key}` },
    el("summary", {}, el("span", {}, summary || "More"), icon("chev", "sm chev")),
    el("div", { class: "body" }, body));
  d.open = openFolds.has(key);
  d.addEventListener("toggle", () => { if (d.open) openFolds.add(key); else openFolds.delete(key); });
  return d;
}

// A part that opens on a click, as the app's Expander: its head stays.
function expander(title, ic, open, ...body) {
  const d = el("details", { class: "card exp" },
    el("summary", {}, icon(ic), el("span", { class: "name" }, title), icon("chev", "sm chev")),
    el("div", { class: "body" }, body));
  d.open = open;
  return d;
}

// The arrow keys move the choice of a row of radio buttons, as in the app's
// Segmented and SchemeSwitch: the row is one stop of the Tab key.
function radioKeys(group) {
  group.addEventListener("keydown", (ev) => {
    const step = { ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1 }[ev.key];
    if (!step) return;
    ev.preventDefault();
    const all = Array.from(group.querySelectorAll("[role=radio]"));
    const next = all[all.findIndex((b) => b.getAttribute("aria-checked") === "true") + step];
    if (next) { next.click(); next.focus(); }
  });
}

function markRadios(group, chosen) {
  for (const b of group.querySelectorAll("[role=radio]")) {
    b.setAttribute("aria-checked", String(b === chosen));
    b.tabIndex = b === chosen ? 0 : -1;
  }
}

// A row of choices of which one is on, as the app's Segmented.
function segmented(label, options, current, onchoose) {
  const box = el("div", { class: "seg", role: "radiogroup", "aria-label": label });
  options.forEach((o, i) => {
    const b = el("button", { type: "button", role: "radio", onclick: () => { markRadios(box, b); onchoose(i); } }, o);
    box.append(b);
  });
  markRadios(box, box.children[current]);
  radioKeys(box);
  return box;
}

// The command reference: `h` is the CLI's help data (`line`, `more` and
// `doc` for each card, verb and option); `first` are parts that come before
// it (the center's Connect a harness and its own commands).
function buildHelp(h, first) {
  // The lines start after `nerve-node`, which the page says once.
  const words = (usage) => usage.replace(/^nerve-node /, "").replace(" [OPTIONS]", "");
  const argRow = (a) => [el("code", {}, a.name), el("span", {}, (a.optional ? "Optional. " : "") + a.line, a.more ? more(`arg:${a.name}:${a.line}`, "More", el("p", {}, a.more)) : null)];
  const args = (list) => el("div", { class: "arg-rows" }, list.flatMap(argRow));
  const view = { q: "", byName: false };
  const docLink = (doc) => doc ? el("p", { class: "meta" }, "More in the user guide: ",
    el("a", { href: `${GUIDE}/${doc}`, target: "_blank", rel: "noopener noreferrer" }, doc)) : null;

  // One row for each card of the CLI definition, one line; it opens on a
  // line per verb, with its options and its long text folded.
  const row = (c, topic) => {
    const alone = c.verbs.length === 1 && c.verbs[0].name === c.name ? c.verbs[0] : null;
    const line = c.line || (alone ? alone.line : c.verbs.map((v) => v.name).join(", "));
    const own = (v) => v.args.concat(c.shared_args || []);
    const verb = (v) => el("div", { class: "verb" },
      el("code", { class: "code" }, words(v.usage)),
      el("p", {}, v.line),
      v.more ? more(`verb:${v.name}`, "More", el("p", {}, v.more)) : null,
      own(v).length ? more(`opts:${v.name}`, `Options (${own(v).length})`, args(own(v))) : null);
    const tag = pill("", topic);
    const d = el("details", { class: "cmd", id: "cmd-" + c.name.replace(/[^\w]+/g, "-") },
      el("summary", {}, el("span", { class: "cmd-name" }, c.name), el("span", { class: "cmd-line" }, line), tag, icon("chev", "sm chev")),
      el("div", { class: "body" },
        c.more ? el("p", {}, c.more) : null,
        alone && words(alone.usage) === c.name && !own(alone).length && !alone.more ? null : c.verbs.map(verb),
        docLink(c.doc)));
    const text = [c.name, c.line, c.more, ...c.verbs.flatMap((v) => [v.name, v.line, v.more, ...own(v).map((a) => `${a.name} ${a.line} ${a.more}`)])].join("\n").toLowerCase();
    return { c, d, tag, text };
  };
  const groups = h.sections.map((s) => {
    const rows = s.cards.map((c) => row(c, s.name));
    const count = pill("accent", String(rows.length));
    const about = s.line ? el("p", { class: "ref-about" }, s.line) : null;
    const body = el("div", { class: "body" });
    const g = el("details", { class: "ref-group" }, el("summary", {}, icon("chev", "sm chev"), s.name, count), body);
    g.open = true;
    return { rows, count, about, body, g };
  });
  const rows = groups.flatMap((g) => g.rows);

  const list = el("div", { class: "ref-list" });
  const none = el("p", { class: "ref-none" }, "No command matches.");
  function render() {
    const q = view.q.trim().toLowerCase();
    const hit = (r) => !q || r.text.includes(q);
    // A match inside a row opens it, so the hit is in sight.
    for (const r of rows) { r.tag.hidden = !view.byName; if (q && hit(r)) r.d.open = true; }
    if (view.byName) {
      const shown = rows.filter(hit).sort((a, b) => a.c.name.localeCompare(b.c.name));
      list.replaceChildren(el("div", { class: "ref-flat" }, shown.map((r) => r.d)));
      none.hidden = shown.length > 0;
      return;
    }
    const parts = groups.filter((g) => {
      const mine = g.rows.filter(hit);
      g.count.textContent = String(mine.length);
      g.body.replaceChildren(...[g.about, ...mine.map((r) => r.d)].filter(Boolean));
      return mine.length > 0;
    });
    list.replaceChildren(...parts.map((g) => g.g));
    none.hidden = parts.length > 0;
  }
  const filter = el("input", {
    class: "input", type: "search", placeholder: "Filter: pair, folder, sudo…", "aria-label": "Filter the commands",
    autocomplete: "off", spellcheck: "false", oninput: () => { view.q = filter.value; render(); },
  });
  render();

  return [
    head("help", "Help", null, null,
      el("a", { class: "btn ghost", href: GUIDE, target: "_blank", rel: "noopener noreferrer" }, icon("external"), "User guide")),
    el("div", { class: "help" },
      ...(first || []),
      expander("nerve-node commands", "terminal", true,
        el("p", { class: "lead" }, "Commands of nerve-node. Run them on the machine itself."),
        el("div", { class: "ref-bar" }, filter,
          segmented("Order", ["By topic", "A to Z"], 0, (i) => { view.byName = i === 1; render(); })),
        none, list,
        h.options && h.options.length ? more("help:options", `Shared options (${h.options.length})`, args(h.options)) : null),
      expander("Keyboard shortcuts", "keyboard", false,
        el("div", { class: "keys" }, HELP_KEYS.map(([k, does]) => el("div", { class: "key-row" }, el("kbd", {}, k), el("span", {}, does)))))),
  ];
}

// ---- Theme ----

const THEME_KEY = "nerve.theme";
const light = matchMedia("(prefers-color-scheme: light)");

function storedTheme() {
  try { return localStorage.getItem(THEME_KEY) || "system"; } catch (_) { return "system"; }
}

// Light or dark in one step: no control fades on its own while the rest has
// changed (the switching class holds their transitions for a frame).
function applyTheme(choice, animate) {
  const root = document.documentElement;
  const dark = choice === "dark" || (choice !== "light" && !light.matches);
  if (animate) {
    root.classList.add("switching");
    requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove("switching")));
  }
  root.dataset.theme = dark ? "dark" : "light";
  const m = document.querySelector('meta[name="theme-color"]');
  if (m) m.content = dark ? "#0f1116" : "#f4f5f9";
  markRadios($("theme"), document.querySelector(`[data-theme-choice="${choice}"]`));
}

for (const b of document.querySelectorAll("[data-theme-choice]")) {
  b.addEventListener("click", () => {
    try { localStorage.setItem(THEME_KEY, b.dataset.themeChoice); } catch (_) { /* storage blocked: lasts until reload */ }
    applyTheme(b.dataset.themeChoice, true);
  });
}
radioKeys($("theme"));
light.addEventListener("change", () => { if (storedTheme() === "system") applyTheme("system", true); });
applyTheme(storedTheme(), false);

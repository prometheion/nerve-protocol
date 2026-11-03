// A smoke test of a web UI of Nerve (the center's or the node's) in a real
// browser: headless Chrome, driven over the DevTools protocol with what
// Node.js has built in (fetch, WebSocket), so it needs no package. It signs
// in with the token on the login page, as a person does, then opens every
// page of the sidebar and fails on a script error, an error in the console,
// an answer of 500 or more, or a page that shows nothing.
//
//   node web-ui-smoke.mjs <chrome> <url> <token>
//
// The browser runs without its sandbox, as root may run it on a disposable
// CI machine, with a profile of its own that is deleted at the end.

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [chromeBin, url, token] = process.argv.slice(2);
if (!chromeBin || !url || !token) {
  console.error("usage: node web-ui-smoke.mjs <chrome> <url> <token>");
  process.exit(2);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const problems = [];
const profile = mkdtempSync(join(tmpdir(), "nerve-ui-smoke-"));
const chrome = spawn(chromeBin, [
  "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
  "--no-default-browser-check", "--remote-debugging-port=0",
  `--user-data-dir=${profile}`, "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });

function end(code) {
  chrome.kill("SIGKILL");
  try { rmSync(profile, { recursive: true, force: true }); } catch (_) { /* gone with the machine */ }
  process.exit(code);
}
setTimeout(() => { console.error("the smoke test took longer than 3 minutes"); end(1); }, 180000).unref();

// The browser says where its DevTools endpoint is on stderr.
const port = await new Promise((resolve, reject) => {
  let text = "";
  chrome.stderr.on("data", (d) => {
    text += d;
    const m = text.match(/DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//);
    if (m) resolve(m[1]);
  });
  chrome.on("exit", (c) => reject(new Error(`the browser ended (${c}): ${text}`)));
}).catch((e) => { console.error(e.message); end(1); });

const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const target = pages.find((p) => p.type === "page");
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });

let next = 1;
const waiting = new Map();
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && waiting.has(m.id)) {
    const { resolve, reject } = waiting.get(m.id);
    waiting.delete(m.id);
    if (m.error) reject(new Error(m.error.message));
    else resolve(m.result);
    return;
  }
  const p = m.params || {};
  if (m.method === "Runtime.exceptionThrown") {
    const d = p.exceptionDetails || {};
    problems.push(`script error: ${(d.exception && d.exception.description) || d.text} (${d.url || ""}:${d.lineNumber})`);
  } else if (m.method === "Runtime.consoleAPICalled" && p.type === "error") {
    problems.push(`console error: ${(p.args || []).map((a) => a.value ?? a.description).join(" ")}`);
  } else if (m.method === "Network.responseReceived" && p.response.status >= 500) {
    problems.push(`answer ${p.response.status} for ${p.response.url}`);
  }
};
function send(method, params = {}) {
  const id = next++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => waiting.set(id, { resolve, reject }));
}
async function evaluate(expression) {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`${expression}: ${r.exceptionDetails.text}`);
  return r.result.value;
}
async function until(what, expression, ms = 15000) {
  for (let t = 0; t < ms; t += 200) {
    if (await evaluate(expression).catch(() => false)) return;
    await sleep(200);
  }
  throw new Error(`${what} did not happen within ${ms / 1000} s`);
}

try {
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Page.enable");
  await send("Page.navigate", { url });
  await until("the login page", "!!document.querySelector('.login-form')");
  // As a person signs in: the token in the field, then the button.
  await evaluate(`(() => {
    const input = document.querySelector('.login-input');
    input.value = ${JSON.stringify(token)};
    document.querySelector('.login-form').requestSubmit();
    return true;
  })()`);
  await until("the app after signing in", "!!document.getElementById('page') && document.getElementById('page').children.length > 0");
  const names = await evaluate("[...new Set([...document.querySelectorAll('[data-page]')].map((a) => a.dataset.page))]");
  if (!names.length) throw new Error("the sidebar has no pages");
  for (const name of names) {
    await evaluate(`(() => { location.hash = ${JSON.stringify(name)}; return true; })()`);
    await until(`the page ${name}`, `document.querySelector('[data-page="${name}"][aria-current="page"]') !== null && document.getElementById('page').children.length > 0`);
    // What the page asks for when it opens comes in meanwhile.
    await sleep(1500);
    const shown = await evaluate("document.getElementById('page').innerText.trim().length");
    const title = await evaluate("document.getElementById('top-title').textContent");
    console.log(`page ${name}: "${title}", ${shown} characters`);
    if (!shown) problems.push(`the page ${name} shows nothing`);
  }
} catch (e) {
  problems.push(e.message);
}

if (problems.length) {
  for (const p of problems) console.log(`::error::web UI ${url}: ${p}`);
  end(1);
}
console.log(`web UI ${url}: every page opened, no error`);
end(0);

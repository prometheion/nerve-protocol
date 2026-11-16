// Mounts a whole web UI on a page of it, with a fake server answering from
// the example data; `routes` adds or replaces answers.
import { CenterApp } from "../center/App";
import { NodeApp } from "../node/App";
import { render, settle } from "./dom";
import { fakeServer, type Call } from "./fake";
import { centerData, nodeData } from "./fixtures";

type Routes = Record<string, (c: Call) => unknown>;

export function centerRoutes(d = centerData()): Routes {
  return {
    "GET /api/overview": () => d.overview,
    "GET /api/stats": () => d.stats,
    "GET /api/audit": () => d.audit,
    "GET /api/checker": () => d.checker,
    "GET /api/log": () => d.log,
    "GET /api/center": () => d.center,
    "GET /api/tokens": () => d.tokens,
    "GET /api/help": () => d.help,
    "GET /api/caps": (c) => d.caps(c.query.get("id") || ""),
  };
}

export function nodeRoutes(d = nodeData()): Routes {
  return {
    "GET /api/overview": () => d.overview,
    "GET /api/perm": () => d.perm,
    "GET /api/caps": () => d.caps,
    "GET /api/relay": () => d.relay,
    "GET /api/audit": () => d.audit,
    "GET /api/log": () => d.log,
    "GET /api/settings": () => d.settings,
    "GET /api/ui": () => d.ui,
    "GET /api/help": () => d.help,
  };
}

export async function center(page: string, routes: Routes = {}) {
  location.hash = page;
  const f = fakeServer({ ...centerRoutes(), ...routes });
  const el = await render(<CenterApp />);
  await settle(6);
  return { el, f };
}

export async function node(page: string, routes: Routes = {}) {
  location.hash = page;
  const f = fakeServer({ ...nodeRoutes(), ...routes });
  const el = await render(<NodeApp />);
  await settle(6);
  return { el, f };
}

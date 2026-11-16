// The node's web UI: its pages in the app's layout B. Every change is one
// command of the CLI that the node runs for its owner. The node's status is
// asked every two seconds for every page; each page asks for what else it
// shows.
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { api } from "../api";
import { Shell, usePoll, useHashPage, useReach, type PageDef, type Poll } from "../frame";
import { Loading } from "../ui";
import { AuditPage } from "./Audit";
import { CapsPage } from "./Caps";
import { CentersPage, PairCenter } from "./Centers";
import { HelpPage } from "./Help";
import { LogPage } from "./Log";
import { OverviewPage } from "./Overview";
import { PermissionsPage } from "./Permissions";
import { RelayPage } from "./Relay";
import { SettingsPage } from "./Settings";
import type { Status } from "./types";

export const PAGES: PageDef[] = [
  { id: "overview", title: "Overview", icon: "overview" },
  { id: "centers", title: "Centers", icon: "centers" },
  { id: "relay", title: "Relay", icon: "route" },
  { id: "permissions", title: "Permissions", icon: "shield" },
  { id: "capabilities", title: "Capabilities", icon: "plug" },
  { id: "audit", title: "Audit", icon: "audit" },
  { id: "log", title: "Log", icon: "log" },
  { id: "settings", title: "Settings", icon: "settings", bottom: true },
  { id: "help", title: "Help", icon: "help", bottom: true },
];

export type NodeCtx = {
  o: Status;
  status: Poll<Status>;
  /** The center the Permissions and Capabilities pages show. */
  center: string | null;
  setCenter: (c: string) => void;
  /** Opens Pair a center. */
  pair: () => void;
};

export const NodeContext = createContext<NodeCtx | null>(null);

export function useNode(): NodeCtx {
  return useContext(NodeContext)!;
}

const VIEWS: Record<string, () => ReactNode> = {
  overview: OverviewPage,
  centers: CentersPage,
  relay: RelayPage,
  permissions: PermissionsPage,
  capabilities: CapsPage,
  audit: AuditPage,
  log: LogPage,
  settings: SettingsPage,
  help: HelpPage,
};

export function NodeApp() {
  const page = useHashPage(PAGES);
  const status = usePoll(() => api<Status>("GET", "/api/overview"), []);
  useReach(status.error, status.data, "node");
  const [picked, setCenter] = useState<string | null>(null);
  const [pairing, setPairing] = useState(false);
  const closePair = useCallback(() => setPairing(false), []);
  const o = status.data;
  const centers = o ? o.centers : [];
  // The center picked, or the first while the picked one is gone.
  const center = centers.some((c) => c.name === picked) ? picked : centers.length ? centers[0].name : null;
  const up = centers.filter((c) => c.status === "connected").length;
  const shown = o
    ? o.locked
      ? { tone: "warn" as const, title: "Locked", line: "Nothing runs until you unlock" }
      : { tone: "ok" as const, title: "Running", line: `${up} of ${centers.length} ${centers.length === 1 ? "center" : "centers"} linked` }
    : null;
  const View = VIEWS[page];
  return (
    <Shell role="node" pages={PAGES} page={page} status={shown}>
      {o ? (
        <NodeContext.Provider value={{ o, status, center, setCenter, pair: () => setPairing(true) }}>
          <View />
          {pairing ? <PairCenter onClose={closePair} /> : null}
        </NodeContext.Provider>
      ) : (
        <Loading />
      )}
    </Shell>
  );
}

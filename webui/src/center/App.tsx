// The center's web UI: its pages in the app's layout B. The overview (the
// machines, the sessions, how harnesses connect) is asked every two seconds
// for every page; each page asks for what else it shows.
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { api } from "../api";
import { Shell, usePoll, useHashPage, useReach, type PageDef, type Poll } from "../frame";
import { plural } from "../format";
import { Loading } from "../ui";
import { AuditPage } from "./Audit";
import { CapsPage } from "./Caps";
import { CheckerPage } from "./Checker";
import { HarnessesPage } from "./Harnesses";
import { HelpPage } from "./Help";
import { LogPage } from "./Log";
import { NodesPage, PairOverlay } from "./Nodes";
import { OverviewPage } from "./Overview";
import { SettingsPage } from "./Settings";
import { StatsPage } from "./Stats";
import type { Overview, PairedNode } from "./types";

export const PAGES: PageDef[] = [
  { id: "overview", title: "Overview", icon: "overview" },
  { id: "nodes", title: "Nodes", icon: "server" },
  { id: "harnesses", title: "Harnesses", icon: "terminal" },
  { id: "checker", title: "Action checker", icon: "octagon" },
  { id: "capabilities", title: "Capabilities", icon: "plug" },
  { id: "stats", title: "Statistics", icon: "gauge" },
  { id: "audit", title: "Audit", icon: "audit" },
  { id: "log", title: "Log", icon: "log" },
  { id: "settings", title: "Settings", icon: "settings", bottom: true },
  { id: "help", title: "Help", icon: "help", bottom: true },
];

export type Center = {
  ov: Overview;
  overview: Poll<Overview>;
  /** The machine a pairing just paired, for its next step. */
  paired: PairedNode | null;
  setPaired: (n: PairedNode | null) => void;
  /** Opens Pair a machine. */
  pair: () => void;
};

export const CenterCtx = createContext<Center | null>(null);

export function useCenter(): Center {
  return useContext(CenterCtx)!;
}

const VIEWS: Record<string, () => ReactNode> = {
  overview: OverviewPage,
  nodes: NodesPage,
  harnesses: HarnessesPage,
  checker: CheckerPage,
  capabilities: CapsPage,
  stats: StatsPage,
  audit: AuditPage,
  log: LogPage,
  settings: SettingsPage,
  help: HelpPage,
};

export function CenterApp() {
  const page = useHashPage(PAGES);
  const overview = usePoll(() => api<Overview>("GET", "/api/overview"), []);
  useReach(overview.error, overview.data, "center");
  const [paired, setPaired] = useState<PairedNode | null>(null);
  const [pairing, setPairing] = useState(false);
  const closePair = useCallback(() => setPairing(false), []);
  const reloadOv = overview.reload;
  const onPaired = useCallback(
    (n: PairedNode) => {
      setPairing(false);
      setPaired(n);
      reloadOv();
    },
    [reloadOv],
  );
  const ov = overview.data;
  const online = ov ? ov.nodes.filter((n) => n.online).length : 0;
  const status = ov ? { tone: "ok" as const, title: "Running", line: ov.nodes.length ? `${online} of ${plural(ov.nodes.length, "node")} online` : "No node paired yet" } : null;
  const View = VIEWS[page];
  return (
    <Shell role="center" pages={PAGES} page={page} status={status}>
      {ov ? (
        <CenterCtx.Provider value={{ ov, overview, paired, setPaired, pair: () => setPairing(true) }}>
          <View />
          {pairing ? (
            <PairOverlay onClose={closePair} onPaired={onPaired} />
          ) : null}
        </CenterCtx.Provider>
      ) : (
        <Loading />
      )}
    </Shell>
  );
}

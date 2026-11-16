// The center's web UI: its pages in the app's layout B.
import { Shell, useHashPage, type PageDef } from "../frame";
import { Loading, PageHead } from "../ui";

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

export function CenterApp() {
  const page = useHashPage(PAGES);
  const def = PAGES.find((p) => p.id === page)!;
  return (
    <Shell role="center" pages={PAGES} page={page} status={null}>
      <PageHead icon={def.icon} title={def.title} />
      <Loading />
    </Shell>
  );
}

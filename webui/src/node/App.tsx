// The node's web UI: its pages in the app's layout B.
import { Shell, useHashPage, type PageDef } from "../frame";
import { Loading, PageHead } from "../ui";

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

export function NodeApp() {
  const page = useHashPage(PAGES);
  const def = PAGES.find((p) => p.id === page)!;
  return (
    <Shell role="node" pages={PAGES} page={page} status={null}>
      <PageHead icon={def.icon} title={def.title} />
      <Loading />
    </Shell>
  );
}

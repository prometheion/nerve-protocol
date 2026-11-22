// What the node's API answers, as far as the pages read it
// (crates/nerve-node/src/webui.rs and webui/pages.rs).

export type CenterEntry = {
  name: string;
  url: string;
  status: string;
  mode: string;
  until?: number | null;
  then?: string | null;
  folders?: number;
  allow_rules?: number;
  deny_rules?: number;
  sudo_rules?: number;
  as_owner?: boolean;
  no_network?: boolean;
  network_off?: string | null;
  account?: string | null;
  settings?: string;
  paused?: boolean;
  revoked?: boolean;
  unknown?: boolean;
};

export type Status = {
  locked: boolean;
  /** The node's platform, `linux` or `windows`. */
  os?: string;
  owner?: string | null;
  owner_full_rights?: boolean;
  installed?: boolean;
  confinement?: string | null;
  running: number;
  sudo?: string;
  network_rules?: boolean;
  pairings_warning?: string | null;
  centers: CenterEntry[];
  relay?: unknown;
};

export type Json = any;

/** Whether the node runs on Windows, where there is no nerve-node to type
 * (the Nerve app does what its commands do), no root and no systemctl
 * (#213, W4-1: the pages gave Linux commands there). */
export const onWindows = (o?: { os?: string } | null) => !!o && o.os === "windows";

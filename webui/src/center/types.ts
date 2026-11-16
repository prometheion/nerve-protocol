// What the center's API answers, as far as the pages read it
// (crates/nerve-center/src/ui.rs).

export type Cap = { id: string; summary?: string; exposure?: string };
export type Broken = { name: string; reason: string };

export type Node = {
  id: string;
  name: string;
  online: boolean;
  status?: string;
  disabled: boolean;
  platform: string;
  arch: string;
  since_ms?: number;
  last_seen_ms?: number;
  paired_ms?: number;
  going_away?: string | null;
  summary?: string;
  capabilities?: Cap[];
  broken?: Broken[];
  folders?: number | null;
  settings_write?: boolean;
};

export type Session = { id: string; client?: string; transport: string; tainted?: boolean; started_ms: number; calls: number; nodes: string[] };

export type Mcp = { mode: "stdio" | "http" | "off"; url?: string; fingerprint?: string | null };

export type Overview = {
  center: { id: string; name: string; url: string; pin?: string; os: string };
  nodes: Node[];
  alerts: { ts: number; text: string }[];
  sessions: Session[];
  mcp: Mcp;
};

export type PairedNode = { id?: string; name: string; platform?: string };

export type Pairing = { link: string; code: string; expires_ms: number; pin?: string | null };

export type Json = any;

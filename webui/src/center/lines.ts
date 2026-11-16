// The center's words that depend on the machine they are about: a Windows
// machine has no nerve-node, and the Nerve app on it does what the commands
// do elsewhere.
import type { Node, Overview } from "./types";

/** The command a Linux machine pairs with: the link comes on its stdin,
 * pasted on the next line, so the unused code never sits in the process
 * list while `center add` waits for the owner's yes (#198). */
export const PAIR_COMMAND = "nerve-node center add -";

/** What a new pairing needs next: in folder mode its commands run only in a
 * folder it was given. */
export const FOLDER_STEP = "nerve-node folder add ~/project rwx";

/** Where the owner gives machine `n` a folder: the nerve-node command, or on
 * a Windows machine, which has none, the Nerve app's place. */
export function folderStep(n?: { platform?: string } | null): { text: string; copy: string | null } {
  return n && n.platform === "windows"
    ? { text: "in the Nerve app on that machine, Permissions › Folders, Add a folder", copy: null }
    : { text: FOLDER_STEP, copy: FOLDER_STEP };
}

/** The line Help adds where a paired machine runs Windows: the nerve-node
 * commands are not for it, as it has no nerve-node. */
export function windowsHelpNote(o: Overview | null): string | null {
  return o && o.nodes.some((n) => n.platform === "windows")
    ? "A Windows machine has no nerve-node: the Nerve app on it does what these commands do, and its Help says where."
    : null;
}

/** Whether this center runs on Windows, where its service commands run in
 * an administrator's terminal, not with sudo. */
export function centerOnWindows(o: Overview | null): boolean {
  return !!o && o.center.os === "windows";
}

/** The line that puts the sudo command `command` on the list exactly as it
 * is, the rule the audit buttons made: --exact keeps a trailing * the
 * command's own, where it would be a wildcard, every command that starts
 * so, as root. Null where a line to copy could not be trusted: inside
 * single quotes a word reads the same in POSIX shells and in fish unless it
 * holds a quote or a backslash (fish reads \' and \\ there), and a line
 * break would run what is before it when pasted. */
export function sudoRuleLine(command: string): string | null {
  if (/['\\\u0000-\u001f\u007f]/.test(command)) return null;
  return `nerve-node rule add allow --action exec.run --exact '${command}'`;
}

/** Whether an audit entry's call ran sudo. */
export const isSudo = (cap: string, action: string, target?: string) =>
  cap === "exec" && action === "run" && /^\s*(\S*\/)?sudo(\s|$)/.test(target || "");

/** Whether an entry's target was cut to its start: then it names no call,
 * which only matters where a rule names the target (a command line or a
 * path). */
export const isCut = (cap: string, action: string, target?: string) =>
  (cap === "fs" || (cap === "exec" && action === "run")) && /… \[cut at \d+ of \d+ characters\]$/.test(target || "");

/** The state of a machine as a word and a tone. */
export function nodeState(n: Node): { word: string; tone: "ok" | "warn" | "" } {
  if (n.disabled) return { word: "disabled", tone: "warn" };
  return n.online ? { word: n.status || "online", tone: "ok" } : { word: "offline", tone: "" };
}

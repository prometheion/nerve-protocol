// The shared building blocks of layout B.
import { act, useState } from "react";
import { expect, it, vi } from "vitest";
import { button, click, key, render, text, type } from "./test/dom";
import { Asks, Btn, GrowArea, LRow, ListCard, Overlay, Picker, RemoveAsk, Seg, Split, ask, paneShare, rowsFor } from "./ui";

it("asks before a removal, in place, and removes only on yes", async () => {
  const gone = vi.fn(async () => {});
  const el = await render(<RemoveAsk question="Remove dev?" onConfirm={gone} />);
  await click(button(el, "Remove"));
  expect(text(el)).toContain("Remove dev?");
  await click(button(el, "Cancel"));
  expect(gone).not.toHaveBeenCalled();
  expect(text(el)).not.toContain("Remove dev?");
  await click(button(el, "Remove"));
  const yes = el.querySelectorAll("button")[1];
  await click(yes);
  expect(gone).toHaveBeenCalledTimes(1);
});

it("ignores the second click of a double-click on the confirm", async () => {
  const gone = vi.fn(async () => {});
  const el = await render(<RemoveAsk question="Remove dev?" onConfirm={gone} bare label="Remove" />);
  await click(el.querySelector("button"));
  const yes = el.querySelector(".ask .btn.danger-solid")!;
  await act(async () => {
    yes.dispatchEvent(new MouseEvent("click", { bubbles: true, detail: 2 }));
  });
  expect(gone).not.toHaveBeenCalled();
  await act(async () => {
    yes.dispatchEvent(new MouseEvent("click", { bubbles: true, detail: 1 }));
  });
  expect(gone).toHaveBeenCalledTimes(1);
});

function Picked() {
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState("a");
  return (
    <Split
      open={open}
      onBack={() => setOpen(false)}
      list={
        <ListCard>
          {["a", "b"].map((x) => (
            <LRow key={x} current={sel === x} onPick={() => (setSel(x), setOpen(true))}>
              row {x}
            </LRow>
          ))}
        </ListCard>
      }
      detail={<div className="card">details of {sel}</div>}
    />
  );
}

it("shows the picked row's details, and Back goes to the list on a small window", async () => {
  const el = await render(<Picked />);
  const split = el.querySelector(".split")!;
  expect(split.classList.contains("open")).toBe(false);
  await click(el.querySelectorAll(".lrow")[1]);
  expect(text(el)).toContain("details of b");
  expect(el.querySelectorAll(".lrow")[1].getAttribute("aria-current")).toBe("true");
  expect(split.classList.contains("open")).toBe(true);
  await click(button(el, "Back to the list"));
  expect(split.classList.contains("open")).toBe(false);
  // Enter picks a row too.
  await key(el.querySelectorAll(".lrow")[0], "Enter");
  expect(text(el)).toContain("details of a");
});

it("moves a row of choices with the arrow keys", async () => {
  const chose = vi.fn();
  const el = await render(<Seg label="Mode" options={[{ value: "a", label: "A" }, { value: "b", label: "B" }]} value="a" onChange={chose} />);
  const group = el.querySelector("[role=radiogroup]")!;
  expect(group.querySelectorAll("[aria-checked=true]")[0].textContent).toBe("A");
  await key(group, "ArrowRight");
  expect(chose).toHaveBeenCalledWith("b");
});

it("closes an overlay with Esc", async () => {
  const close = vi.fn();
  await render(<Overlay title="Pair a machine" onClose={close}>x</Overlay>);
  expect(document.querySelector("[role=dialog]")?.getAttribute("aria-modal")).toBe("true");
  await key(document.body, "Escape");
  expect(close).toHaveBeenCalled();
});

// The page is a size container, which holds a fixed scrim inside it: the
// window over the page belongs to the document's body (#213, review).
it("draws an overlay over the window, not inside the page", async () => {
  await render(
    <main className="page">
      <Overlay title="Pair a machine" onClose={() => {}}>
        x
      </Overlay>
    </main>,
  );
  const scrim = document.querySelector(".scrim");
  expect(scrim?.parentElement).toBe(document.body);
  expect(scrim?.closest(".page")).toBeNull();
});

it("puts the focus in an overlay's field, not on its Close", async () => {
  await render(
    <Overlay title="Rename" onClose={() => {}} foot={<Btn kind="primary">Rename</Btn>}>
      <input aria-label="Name" />
    </Overlay>,
  );
  expect(document.activeElement?.getAttribute("aria-label")).toBe("Name");
  await render(
    <Overlay title="Sure?" onClose={() => {}} foot={<Btn kind="primary">Yes</Btn>}>
      x
    </Overlay>,
  );
  expect(document.activeElement?.textContent).toBe("Yes");
});

it("puts the focus of a question without a field on Cancel, so Enter does not say yes", async () => {
  await render(<Asks />);
  let answer: unknown = "open";
  await act(async () => {
    void ask({ title: "Add to the sudo allow list?", message: "sudo apt *", confirm: "Add" }).then((v) => (answer = v));
  });
  expect(document.activeElement?.textContent).toBe("Cancel");
  await click(document.activeElement);
  expect(answer).toBeNull();
});

it("picks an entry of a long list by its search", async () => {
  const pick = vi.fn();
  const items = ["alpha", "beta", "gamma"].map((v) => ({ value: v, text: v }));
  const el = await render(<Picker label="Machine" items={items} value="alpha" onPick={pick} />);
  await click(el.querySelector(".picker-btn"));
  const search = el.querySelector("input[role=combobox]")!;
  await type(search, "gam");
  expect(el.querySelectorAll("[role=option]")).toHaveLength(1);
  await key(search, "Enter");
  expect(pick).toHaveBeenCalledWith("gamma");
  expect(el.querySelector("[role=option]")).toBeNull();
});

it("shows what an action that failed says, and is busy while it runs", async () => {
  let done!: () => void;
  const el = await render(
    <>
      <Btn act={() => new Promise<void>((r) => (done = r))}>Wait</Btn>
      <Btn act={async () => { throw new Error("the center refused"); }}>Fail</Btn>
    </>,
  );
  const { Toasts } = await import("./ui");
  const t = await render(<Toasts />);
  await click(button(el, "Wait"));
  expect(el.querySelector("button")!.getAttribute("aria-busy")).toBe("true");
  expect(el.querySelector("button")!.disabled).toBe(true);
  done();
  await click(button(el, "Fail"));
  expect(text(t)).toContain("the center refused");
});

// The panes of a Split are resized by their gap, the width is kept per page
// in this browser, and a double-click gives the page its own width back
// (owner's finding on pre2: the panes could not be resized).
it("resizes the list by its gap, keeps the width per page, and resets it on a double-click", async () => {
  location.hash = "capabilities";
  // A store of this test's own: the test runner's Node has no localStorage.
  const kept = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => kept.get(k) ?? null,
    setItem: (k: string, v: string) => kept.set(k, v),
    removeItem: (k: string) => kept.delete(k),
  });
  const pane = () => <Split variant="caps" open={false} onBack={() => {}} list={<ListCard>list</ListCard>} detail={<p>details</p>} />;
  let el = await render(pane());
  const split = () => el.querySelector(".split")!;
  const gutter = () => el.querySelector("[role=separator]")!;
  expect(split().hasAttribute("data-w")).toBe(false);
  // The panes measure nothing here, so they meet at half; a step to the
  // right widens the list.
  await key(gutter(), "ArrowRight");
  expect(split().getAttribute("data-w")).toBe("52");
  expect(kept.get("nerve.pane.capabilities.caps")).toBe("52");
  // Another page has its own.
  location.hash = "audit";
  el = await render(pane());
  expect(split().hasAttribute("data-w")).toBe(false);
  location.hash = "capabilities";
  el = await render(pane());
  expect(split().getAttribute("data-w")).toBe("52");
  await act(async () => {
    gutter().dispatchEvent(new MouseEvent("dblclick", { bubbles: true }));
  });
  expect(split().hasAttribute("data-w")).toBe(false);
  expect(kept.has("nerve.pane.capabilities.caps")).toBe(false);
  vi.unstubAllGlobals();
});

it("takes a dragged width on the stylesheet's steps, and stops at each pane's least width", () => {
  expect(paneShare(450, 100, 1100)).toBe(36);
  expect(paneShare(451, 100, 1100)).toBe(36);
  // The list keeps 260 px of 1000, the details 400 px.
  expect(paneShare(110, 100, 1100)).toBe(26);
  expect(paneShare(1090, 100, 1100)).toBe(60);
  // On a wide page the steps' own bounds hold.
  expect(paneShare(0, 0, 3000)).toBe(20);
  expect(paneShare(3000, 0, 3000)).toBe(76);
});

// JSON and command fields grow with their text (owner's finding on pre2:
// the Arguments and Result fields showed a few short lines).
it("grows a field with its text, and keeps a command on one line", async () => {
  expect(rowsFor("", 4)).toBe(4);
  expect(rowsFor('{\n  "type": "object",\n  "properties": {\n    "path": {"type": "string"}\n  }\n}', 4)).toBe(7);
  expect(rowsFor("x".repeat(150), 1)).toBe(3);
  expect(rowsFor("x\n".repeat(100), 4)).toBe(24);
  let said = "";
  const el = await render(<GrowArea oneLine value="" onChange={(v) => (said = v)} aria-label="Command" />);
  const area = el.querySelector("textarea")!;
  expect(area.getAttribute("rows")).toBe("1");
  await type(area, "tail -n 20\n-- {path}");
  expect(said).toBe("tail -n 20 -- {path}");
});

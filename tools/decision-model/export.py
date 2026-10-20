"""Convert a merged Laya-layout checkpoint (train.py's `merged/`, or the base
model's folder) to a Q8_0 GGUF with the converter of the llama.cpp build the
center pins (b11719, crates/nerve-center/src/checker/install.rs).

    python export.py --checkpoint DIR [--out DIR] [--quant q8_0]

Unsloth's decision-model export does the work: it runs that build's
`convert_hf_to_gguf.py` (llama.cpp's `ModernBertDecisionModel`) and then
writes the calibrated temperatures and the served head length into the GGUF
exactly as PyTorch serving uses them, and checks them. The converter comes
from `NERVE_LLAMA_SRC` (default `llama/src-b11719`), never from a download.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

from common import WORK

LLAMA_SRC = Path(os.environ.get("NERVE_LLAMA_SRC", WORK / "llama" / "src-b11719"))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--checkpoint", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=None, help="default <checkpoint>/../gguf")
    ap.add_argument("--quant", default="q8_0")
    a = ap.parse_args()
    out = a.out or a.checkpoint.parent / "gguf"
    if not (LLAMA_SRC / "convert_hf_to_gguf.py").is_file():
        raise SystemExit(f"no llama.cpp converter at {LLAMA_SRC} (set NERVE_LLAMA_SRC)")
    # Read by Unsloth: the converter scripts of this checkout, not its own pinned tag.
    os.environ["UNSLOTH_LLAMA_CPP_SCRIPTS_DIR"] = str(LLAMA_SRC)

    from unsloth.models.decision_gguf import export_decision_gguf

    info = export_decision_gguf(str(a.checkpoint), a.quant, output_dir=str(out), print_output=True)
    ggufs = sorted(out.glob("*.gguf"))
    summary = {"checkpoint": str(a.checkpoint), "converter": str(LLAMA_SRC),
               "files": {g.name: {"bytes": g.stat().st_size, "sha256": sha256(g)} for g in ggufs},
               "export": info}
    (out / "export-summary.json").write_text(json.dumps(summary, indent=1, default=str) + "\n")
    print(json.dumps(summary["files"], indent=1))


if __name__ == "__main__":
    main()

"""Convert a merged Laya-layout checkpoint (train.py's `merged/`, or the base
model's folder) to a Q8_0 GGUF with the converter of the llama.cpp build the
center pins (b11719, crates/nerve-center/src/checker/install.rs).

    python export.py --checkpoint DIR [--out DIR] [--quant q8_0]

Unsloth's decision-model export does the work: it runs that build's
`convert_hf_to_gguf.py` (llama.cpp's `ModernBertDecisionModel`) and then
writes the calibrated temperatures and the served head length into the GGUF
exactly as PyTorch serving uses them, and checks them. The converter comes
from `NERVE_LLAMA_SRC` (default `llama/src-b11719`), never from a download.

`--family d1` (a d1-3B checkpoint folder written by `train.py --family d1`):
no Unsloth, no temperatures (d1 has none, the stock GGUF neither). The
converter's `D1Model` writes a bf16 or Q8_0 GGUF; `--quant` may list
`q8_0`, `bf16`, `f16` and any `llama-quantize` type (e.g. `q4_k_m`, made
from the bf16 file with the pinned build's `llama-quantize`).
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


LLAMA_BIN = Path(os.environ.get("NERVE_LLAMA_BIN", WORK / "llama" / "bin-b11719" / "llama-b11719"))
CONVERTED = ("q8_0", "bf16", "f16")


def export_d1(a, out):
    """d1-3B: the pinned converter on the checkpoint folder, then llama-quantize."""
    import subprocess
    import sys
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CUDA_VISIBLE_DEVICES="",
               PYTHONPATH=f"{LLAMA_SRC / 'gguf-py'}:{os.environ.get('PYTHONPATH', '')}")
    stem = a.checkpoint.parent.name if a.checkpoint.name == "merged" else a.checkpoint.name
    made = {}

    def convert(outtype):
        path = out / f"{stem}-{outtype.upper()}.gguf"
        subprocess.run([sys.executable, str(LLAMA_SRC / "convert_hf_to_gguf.py"), str(a.checkpoint),
                        "--outfile", str(path), "--outtype", outtype], check=True, env=env)
        made[outtype] = path
        return path

    for q in a.quant:
        q = q.lower()
        if q in CONVERTED:
            convert(q)
        else:
            base = made.get("bf16") or out / f"{stem}-BF16.gguf"
            if not base.is_file():
                base = convert("bf16")
            path = out / f"{stem}-{q.upper()}.gguf"
            lib = dict(os.environ, LD_LIBRARY_PATH=f"{LLAMA_BIN}:{os.environ.get('LD_LIBRARY_PATH', '')}")
            subprocess.run([str(LLAMA_BIN / "llama-quantize"), str(base), str(path), q.upper()],
                           check=True, env=lib)
            made[q] = path
    summary = {"checkpoint": str(a.checkpoint), "converter": str(LLAMA_SRC),
               "files": {g.name: {"bytes": g.stat().st_size, "sha256": sha256(g)}
                         for g in sorted(out.glob("*.gguf"))}}
    (out / "export-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary["files"], indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--checkpoint", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=None, help="default <checkpoint>/../gguf")
    ap.add_argument("--quant", nargs="+", default=["q8_0"])
    ap.add_argument("--family", choices=["laya", "d1"], default="laya")
    a = ap.parse_args()
    out = a.out or a.checkpoint.parent / "gguf"
    if not (LLAMA_SRC / "convert_hf_to_gguf.py").is_file():
        raise SystemExit(f"no llama.cpp converter at {LLAMA_SRC} (set NERVE_LLAMA_SRC)")
    if a.family == "d1":
        return export_d1(a, out)
    if len(a.quant) != 1:
        raise SystemExit("Laya exports one quantization at a time")
    a.quant = a.quant[0]
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

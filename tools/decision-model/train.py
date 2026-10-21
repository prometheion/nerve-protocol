"""Fine-tune Laya (or another Laya-layout decision model) on the prepared
rows with Unsloth's FastDecisionModel, calibrate its temperature on the
calibration rows, and save the merged 16-bit checkpoint.

    python train.py --data DIR --name NAME [--family laya|d1] [--mode lora|full] [--epochs N] ...

`--data` is prepare.py's output (`train.jsonl`, `calib.jsonl`). Weights load
and train in bf16 (a normal LoRA, not QLoRA; or `--mode full`). Writes
`runs/<name>/merged/` (the layout llama.cpp's Laya converter reads; export.py
turns it into a GGUF) and `runs/<name>/train.json` (settings, loss, the
calibration metrics). It prints counts and metrics only.

`--family d1` trains LiquidAI's d1-3B instead (d1.py: Unsloth's
FastDecisionModel does not load it, so plain transformers + peft, with the
loss on the same yes/no readout llama.cpp serves).
"""

import argparse
import json
import time
from pathlib import Path

import common
from common import WORK


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--family", choices=["laya", "d1"], default="laya")
    ap.add_argument("--base", default=None,
                    help="the base checkpoint folder: Laya's (rl_agent_config.json, encoder/, "
                         "tokenizer/; default hf/laya) or d1-3B's (default hf/d1-3B)")
    ap.add_argument("--out", type=Path, default=None, help="default runs/<name>")
    ap.add_argument("--mode", choices=["lora", "full"], default="lora")
    ap.add_argument("--r", type=int, default=32)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--lr", type=float, default=None,
                    help="default 1e-4 for LoRA, 2e-5 for full fine-tuning")
    ap.add_argument("--head-lr", type=float, default=None, help="default Unsloth's (1e-4)")
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--grad-accum", type=int, default=2)
    ap.add_argument("--max-seq-length", type=int, default=None,
                    help="default 512 for Laya, 4096 for d1 (the longest prompt must fit)")
    ap.add_argument("--max-tokens", type=int, default=12000,
                    help="d1: padded tokens per micro-batch (rows of a step are split by length)")
    ap.add_argument("--lora-dropout", type=float, default=0.0)
    ap.add_argument("--split", type=int, default=15,
                    help="d1 full fine-tuning: layers (of 30) on the first GPU, the rest on the second")
    ap.add_argument("--seed", type=int, default=139)
    a = ap.parse_args()
    out = a.out or WORK / "runs" / a.name
    out.mkdir(parents=True, exist_ok=True)
    lr = a.lr or (1e-4 if a.mode == "lora" else 2e-5)
    a.base = a.base or str(WORK / "hf" / ("d1-3B" if a.family == "d1" else "laya"))
    a.max_seq_length = a.max_seq_length or (4096 if a.family == "d1" else 512)
    if a.family == "d1":
        import d1
        a.lr = a.lr or (1e-4 if a.mode == "lora" else 1e-5)
        return d1.train(a, out)

    # Unsloth first: it patches transformers on import.
    from unsloth import DecisionTrainer, FastDecisionModel
    import torch
    from transformers import TrainingArguments

    model, tokenizer = FastDecisionModel.from_pretrained(
        a.base, max_seq_length=a.max_seq_length, dtype=torch.bfloat16,
        full_finetuning=a.mode == "full", random_state=a.seed)
    if a.mode == "lora":
        model = FastDecisionModel.get_peft_model(
            model, r=a.r, lora_alpha=a.alpha, lora_dropout=0.0, random_state=a.seed)

    train_rows = common.load_jsonl(a.data / "train.jsonl")
    calib_rows = common.load_jsonl(a.data / "calib.jsonl")
    train_items, train_report = FastDecisionModel.build_dataset(train_rows, tokenizer, model)
    calib_items, calib_report = FastDecisionModel.build_dataset(calib_rows, tokenizer, model)
    print(json.dumps({"train": train_report, "calib": calib_report}))
    if train_report["skipped"] or calib_report["skipped"]:
        raise SystemExit("some rows were skipped; see the report above")

    args = TrainingArguments(
        per_device_train_batch_size=a.batch,
        per_device_eval_batch_size=a.batch,
        gradient_accumulation_steps=a.grad_accum,
        num_train_epochs=a.epochs,
        max_steps=a.max_steps,
        warmup_steps=0.05,  # a ratio of the steps (transformers 5)
        learning_rate=lr,
        lr_scheduler_type="cosine",
        weight_decay=0.01,
        bf16=True,
        eval_strategy="epoch" if calib_items else "no",
        save_strategy="no",
        logging_steps=10,
        output_dir=str(out / "trainer"),
        report_to="none",
        seed=a.seed,
    )
    trainer = DecisionTrainer(
        model=model, processing_class=tokenizer, train_dataset=train_items,
        eval_dataset=calib_items or None, args=args, head_learning_rate=a.head_lr)
    started = time.time()
    stats = trainer.train()
    minutes = (time.time() - started) / 60

    # The temperature llama.cpp serves with comes from rl_agent_config.json,
    # which calibrate() updates; fitted on rows that were not trained on.
    calib = FastDecisionModel.calibrate(model, tokenizer, calib_items) if calib_items else {}
    model.save_pretrained_merged(str(out / "merged"), tokenizer)

    record = {
        "base": a.base, "data": str(a.data), "mode": a.mode, "lr": lr, "head_lr": a.head_lr,
        "r": a.r if a.mode == "lora" else None, "alpha": a.alpha if a.mode == "lora" else None,
        "epochs": a.epochs, "max_steps": a.max_steps, "batch": a.batch,
        "grad_accum": a.grad_accum, "seed": a.seed, "train_items": len(train_items),
        "calib_items": len(calib_items), "train_loss": stats.training_loss,
        "minutes": round(minutes, 1), "log": trainer.state.log_history,
        "calibration": {k: v for k, v in calib.items() if isinstance(v, (int, float, str, list))},
        "temperature": model.decision_config.get("temperature"),
    }
    (out / "train.json").write_text(json.dumps(record, indent=1, default=str) + "\n")
    print(json.dumps({k: record[k] for k in ("train_items", "calib_items", "train_loss",
                                             "minutes", "calibration", "temperature")},
                     default=str))
    print(f"merged checkpoint: {out / 'merged'}")


if __name__ == "__main__":
    main()

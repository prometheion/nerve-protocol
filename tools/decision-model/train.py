"""Fine-tune Laya (or another Laya-layout decision model) on the prepared
rows with Unsloth's FastDecisionModel, calibrate its temperature on the
calibration rows, and save the merged 16-bit checkpoint.

    python train.py --data DIR --name NAME [--mode lora|full] [--epochs N] ...

Two options for the next round: `--head-lr` gives the decision head its own
learning rate (default 1e-4, what Unsloth's trainer uses for everything outside
the encoder; `--head-lr body` trains the head at `--lr` like the encoder), and
`--top-layers N` trains only the top N encoder layers (and their final norm;
in LoRA mode only those layers get adapters) while the rest of the encoder
stays as it is. Full fine-tuning of the whole encoder stays the default.

`--data` is prepare.py's output (`train.jsonl`, `calib.jsonl`). Weights load
and train in bf16 (a normal LoRA, not QLoRA; or `--mode full`). Writes
`runs/<name>/merged/` (the layout llama.cpp's Laya converter reads; export.py
turns it into a GGUF) and `runs/<name>/train.json` (settings, loss, the
calibration metrics). It prints counts and metrics only.
"""

import argparse
import json
import re
import time
from pathlib import Path

import common
from common import WORK

# The learning rate Unsloth's DecisionTrainer gives every parameter outside the
# encoder (the decision head) when it is not told otherwise.
HEAD_LR = 1e-4


def head_lr_arg(value):
    """`--head-lr`: a rate, or `body` for the encoder's own rate."""
    return "body" if value == "body" else float(value)


def resolve_lrs(mode, lr, head_lr):
    """(encoder lr, head lr) of a run: the default encoder rate is 1e-4 for
    LoRA and 2e-5 for full fine-tuning; the head's is 1e-4 unless `body`."""
    lr = lr or (1e-4 if mode == "lora" else 2e-5)
    if head_lr is None:
        head_lr = HEAD_LR
    return lr, lr if head_lr == "body" else head_lr


def top_layer_range(n_layers, top_layers):
    """The encoder layers that train: all of them for `top_layers` 0, else
    the top N (a list of layer indices)."""
    if top_layers < 0 or top_layers > n_layers:
        raise SystemExit(f"--top-layers must be between 0 and {n_layers}")
    return list(range(n_layers - top_layers, n_layers)) if top_layers else list(range(n_layers))


# ModernBERT's linear layers (attention Wqkv and Wo, MLP Wi and Wo): what
# "all-linear" adapts in Laya's encoder. PEFT takes `layers_to_transform` only
# with a list of module names, not with "all-linear".
LORA_TARGETS = ["Wqkv", "Wo", "Wi"]


def lora_layer_kwargs(layers, top_layers):
    """get_peft_model arguments that put the adapters on `layers` only; none
    (all layers, "all-linear") when no top-layer limit is set."""
    if not top_layers:
        return {}
    return {"target_modules": LORA_TARGETS, "layers_to_transform": layers,
            "layers_pattern": "layers"}


def layer_trains(name, layers):
    """Whether the encoder parameter `name` trains when only `layers` do: those
    layers and the final norm; the embeddings and the layers below stay frozen."""
    m = re.match(r"layers\.(\d+)\.", name)
    return int(m.group(1)) in layers if m else name.startswith("final_norm")


def freeze_below(encoder, layers):
    """Freeze every encoder parameter that `layer_trains` rules out. Returns
    (trainable, total) parameter counts."""
    keep = set(layers)
    trainable = total = 0
    for name, param in encoder.named_parameters():
        train = layer_trains(name, keep)
        param.requires_grad_(train)
        total += param.numel()
        trainable += param.numel() if train else 0
    return trainable, total


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--base", default=str(WORK / "hf" / "laya"),
                    help="a Laya checkpoint folder (rl_agent_config.json, encoder/, tokenizer/)")
    ap.add_argument("--out", type=Path, default=None, help="default runs/<name>")
    ap.add_argument("--mode", choices=["lora", "full"], default="lora")
    ap.add_argument("--r", type=int, default=32)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--lr", type=float, default=None,
                    help="default 1e-4 for LoRA, 2e-5 for full fine-tuning")
    ap.add_argument("--head-lr", type=head_lr_arg, default=None,
                    help="the decision head's learning rate, or `body` for --lr (default 1e-4, "
                         "Unsloth's; the encoder keeps --lr)")
    ap.add_argument("--top-layers", type=int, default=0,
                    help="train only the top N encoder layers (0: all, the default)")
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--grad-accum", type=int, default=2)
    ap.add_argument("--max-seq-length", type=int, default=512)
    ap.add_argument("--seed", type=int, default=139)
    a = ap.parse_args()
    out = a.out or WORK / "runs" / a.name
    out.mkdir(parents=True, exist_ok=True)
    lr, head_lr = resolve_lrs(a.mode, a.lr, a.head_lr)

    # Unsloth first: it patches transformers on import.
    from unsloth import DecisionTrainer, FastDecisionModel
    import torch
    from transformers import TrainingArguments

    model, tokenizer = FastDecisionModel.from_pretrained(
        a.base, max_seq_length=a.max_seq_length, dtype=torch.bfloat16,
        full_finetuning=a.mode == "full", random_state=a.seed)
    n_layers = model.encoder.config.num_hidden_layers
    layers = top_layer_range(n_layers, a.top_layers)
    encoder_trainable = None
    if a.mode == "lora":
        model = FastDecisionModel.get_peft_model(
            model, r=a.r, lora_alpha=a.alpha, lora_dropout=0.0, random_state=a.seed,
            **lora_layer_kwargs(layers, a.top_layers))
    elif a.top_layers:
        encoder_trainable = freeze_below(model.encoder, layers)
        print(json.dumps({"top_layers": a.top_layers, "encoder_layers": n_layers,
                          "encoder_params_trainable": encoder_trainable[0],
                          "encoder_params": encoder_trainable[1]}))

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
        eval_dataset=calib_items or None, args=args, head_learning_rate=head_lr)
    started = time.time()
    stats = trainer.train()
    minutes = (time.time() - started) / 60

    # The temperature llama.cpp serves with comes from rl_agent_config.json,
    # which calibrate() updates; fitted on rows that were not trained on.
    calib = FastDecisionModel.calibrate(model, tokenizer, calib_items) if calib_items else {}
    model.save_pretrained_merged(str(out / "merged"), tokenizer)

    record = {
        "base": a.base, "data": str(a.data), "mode": a.mode, "lr": lr, "head_lr": head_lr,
        "top_layers": a.top_layers or None, "encoder_layers": n_layers,
        "encoder_params_trainable": encoder_trainable[0] if encoder_trainable else None,
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

"""d1-3B (LiquidAI's System One decision model) as a trainable model.

Unsloth's `FastDecisionModel` loads Laya/Clef checkpoints (an encoder or a
Qwen3.5 plus a typed head) and plain language models with a fresh Clef head.
d1-3B is neither: it is an LFM2-VL language model with no head at all. A
`noul` answer is a softmax over the logits of the "yes" and "no" tokens at the
last position of the prompt (`prompt.py` of the model repo, `d1_labels` in
llama.cpp's `server-decision.cpp`), each side the best of its spellings. So
this module trains exactly that readout with the plain transformers + peft
path: the prompt llama.cpp's `systemone` template writes, a two-way cross
entropy over the pooled yes/no logits at the answer slot, nothing else.

`train.py --family d1` calls `train()`; `export.py --family d1` calls
`write_checkpoint()`'s output through llama.cpp's own converter. Prints counts
and metrics only, never a row.
"""

import json
import math
import random
import time
from pathlib import Path

import common

YES_FORMS = ("yes", "Yes", "YES")
NO_FORMS = ("no", "No", "NO")
# The chat template's head: the BOS is a literal special token.
BOS = "<|startoftext|>"
# Weight-name fragments of the language model's linear layers (attention,
# the gated MLP, the short convolution's projections).
LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "out_proj", "in_proj", "w1", "w2", "w3"]


def prompt_text(state, question):
    """The prompt llama.cpp's `systemone` template renders for a `noul`
    question (conversion/lfm2.py `_systemone_template`, prompt.py `render`)."""
    crit = question.get("criteria")
    extra = f"\nYes: {crit.get('true')}\nNo: {crit.get('false')}" if crit else ""
    return (f"{BOS}<|im_start|>user\n{json.dumps(state, ensure_ascii=False, indent=2)}"
            f"\n\n\nQUESTION:\n{question['instructions']}{extra}"
            "\n\nReply with yes or no only.<|im_end|>\n<|im_start|>assistant\n")


def option_ids(tokenizer):
    """Token ids of each side's single-token spellings."""
    def ids(forms):
        out = []
        for f in forms:
            enc = tokenizer.encode(f, add_special_tokens=False)
            if len(enc) == 1 and enc[0] not in out:
                out.append(enc[0])
        return out
    yes, no = ids(YES_FORMS), ids(NO_FORMS)
    if not yes or not no:
        raise SystemExit("the tokenizer has no single-token yes/no")
    return yes, no


def encode_rows(rows, tokenizer, max_len):
    """(input ids, label) per row, and how many rows were over `max_len`
    tokens (left out; the caller treats that as an error)."""
    items, over = [], 0
    for r in rows:
        (question,) = r["questions"].values()
        ids = tokenizer.encode(prompt_text(r["state"], question), add_special_tokens=False)
        if len(ids) > max_len:
            over += 1
            continue
        items.append((ids, 1 if r["gold"]["danger"] else 0))
    return items, over


def batches(items, rows_per_step, rng):
    """Shuffled steps of `rows_per_step` rows each (the last may be shorter)."""
    order = list(range(len(items)))
    rng.shuffle(order)
    return [order[i:i + rows_per_step] for i in range(0, len(order), rows_per_step)]


def micro_batches(step, items, max_tokens):
    """Split one step's rows by length into micro-batches of at most
    `max_tokens` padded tokens, so activations stay bounded."""
    step = sorted(step, key=lambda i: len(items[i][0]))
    out, cur = [], []
    for i in step:
        longest = max([len(items[j][0]) for j in cur] + [len(items[i][0])])
        if cur and longest * (len(cur) + 1) > max_tokens:
            out.append(cur)
            cur = []
        cur.append(i)
    if cur:
        out.append(cur)
    return out


def collate(idx, items, pad_id, device):
    """Right-padded ids, mask and the position of each row's last token."""
    longest = max(len(items[i][0]) for i in idx)
    ids = [items[i][0] + [pad_id] * (longest - len(items[i][0])) for i in idx]
    mask = [[1] * len(items[i][0]) + [0] * (longest - len(items[i][0])) for i in idx]
    import torch
    return (torch.tensor(ids, device=device), torch.tensor(mask, device=device),
            torch.tensor([len(items[i][0]) - 1 for i in idx], device=device),
            torch.tensor([items[i][1] for i in idx], device=device))


def language_model(model):
    """The text stack of a Lfm2VlForConditionalGeneration (peft-wrapped or not)."""
    base = model.get_base_model() if hasattr(model, "get_base_model") else model
    return base.model.language_model, base.lm_head


def two_way_logits(model, ids, mask, last, yes_ids, no_ids):
    """(batch, 2) logits [no, yes] at each row's last token: the best of each
    side's spellings, as the server reads them."""
    import torch
    lm, head = language_model(model)
    h = lm(input_ids=ids, attention_mask=mask).last_hidden_state
    h = h[torch.arange(h.shape[0], device=h.device), last]
    w = head.weight
    yes = (h @ w[yes_ids].T).float().max(dim=-1).values
    no = (h @ w[no_ids].T).float().max(dim=-1).values
    return torch.stack([no, yes], dim=-1)


def evaluate_items(model, items, pad_id, yes_ids, no_ids, max_tokens, device):
    """Mean loss, accuracy and the probabilities on `items` (no training)."""
    import torch
    import torch.nn.functional as F
    model.eval()
    loss = correct = 0.0
    probs = [0.0] * len(items)
    order = list(range(len(items)))
    with torch.no_grad(), torch.autocast("cuda", dtype=torch.bfloat16):
        for mb in micro_batches(order, items, max_tokens):
            ids, mask, last, y = collate(mb, items, pad_id, device)
            z = two_way_logits(model, ids, mask, last, yes_ids, no_ids)
            loss += F.cross_entropy(z, y, reduction="sum").item()
            p = torch.softmax(z, dim=-1)[:, 1]
            correct += ((p > 0.5).long() == y).sum().item()
            for j, i in enumerate(mb):
                probs[i] = p[j].item()
    model.train()
    n = max(len(items), 1)
    return {"loss": loss / n, "accuracy": correct / n}, probs


def train(a, out):
    """LoRA or full fine-tuning of d1-3B on the prepared rows; writes the
    merged checkpoint to `out/merged` and `out/train.json`."""
    import torch
    import torch.nn.functional as F
    from transformers import AutoModelForImageTextToText, AutoTokenizer

    torch.manual_seed(a.seed)
    rng = random.Random(a.seed)
    device = torch.device("cuda:0")
    tokenizer = AutoTokenizer.from_pretrained(a.base)
    yes_ids, no_ids = option_ids(tokenizer)
    pad_id = tokenizer.pad_token_id

    train_rows = common.load_jsonl(a.data / "train.jsonl")
    calib_rows = common.load_jsonl(a.data / "calib.jsonl")
    train_items, over_t = encode_rows(train_rows, tokenizer, a.max_seq_length)
    calib_items, over_c = encode_rows(calib_rows, tokenizer, a.max_seq_length)
    lengths = sorted(len(i[0]) for i in train_items)
    print(json.dumps({"train": len(train_items), "calib": len(calib_items),
                      "over_max_seq": [over_t, over_c],
                      "tokens_p50_p99_max": [lengths[len(lengths) // 2],
                                             lengths[int(len(lengths) * 0.99)], lengths[-1]],
                      "danger_share": round(sum(y for _, y in train_items) / len(train_items), 3)}))
    if over_t or over_c:
        raise SystemExit("some prompts are over --max-seq-length; raise it")

    model = AutoModelForImageTextToText.from_pretrained(
        a.base, dtype=torch.bfloat16, attn_implementation="sdpa")
    # Text only: the vision tower and projector are not trained and not needed.
    model.model.vision_tower = None
    model.model.multi_modal_projector = None
    model.to(device)
    model.config.use_cache = False
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    model.enable_input_require_grads()

    if a.mode == "lora":
        from peft import LoraConfig, get_peft_model
        target = r".*language_model.*\.(" + "|".join(LORA_TARGETS) + r")"
        cfg = LoraConfig(r=a.r, lora_alpha=a.alpha, lora_dropout=a.lora_dropout,
                         target_modules=target, bias="none")
        model = get_peft_model(model, cfg)
        trainable = [p for p in model.parameters() if p.requires_grad]
    else:
        raise SystemExit("full fine-tuning of d1-3B is in d1_full.py")
    n_train = sum(p.numel() for p in trainable)
    print(json.dumps({"trainable_params": n_train}))

    lr = a.lr or 1e-4
    opt = torch.optim.AdamW(trainable, lr=lr, weight_decay=0.01, betas=(0.9, 0.999))
    rows_per_step = a.batch * a.grad_accum
    steps_per_epoch = math.ceil(len(train_items) / rows_per_step)
    total = a.max_steps if a.max_steps > 0 else int(steps_per_epoch * a.epochs)
    warm = max(1, int(0.05 * total))

    def lr_at(step):
        if step < warm:
            return lr * (step + 1) / warm
        return lr * 0.5 * (1 + math.cos(math.pi * (step - warm) / max(1, total - warm)))

    model.train()
    log, step, started = [], 0, time.time()
    done = False
    epoch = 0
    while not done:
        for st in batches(train_items, rows_per_step, rng):
            if step >= total:
                done = True
                break
            for g in opt.param_groups:
                g["lr"] = lr_at(step)
            loss_sum = 0.0
            for mb in micro_batches(st, train_items, a.max_tokens):
                ids, mask, last, y = collate(mb, train_items, pad_id, device)
                with torch.autocast("cuda", dtype=torch.bfloat16):
                    z = two_way_logits(model, ids, mask, last, yes_ids, no_ids)
                loss = F.cross_entropy(z, y, reduction="sum") / len(st)
                loss.backward()
                loss_sum += loss.item()
            torch.nn.utils.clip_grad_norm_(trainable, 1.0)
            opt.step()
            opt.zero_grad(set_to_none=True)
            step += 1
            if step % 10 == 0 or step == total:
                rec = {"step": step, "of": total, "loss": round(loss_sum, 4),
                       "lr": lr_at(step - 1), "min": round((time.time() - started) / 60, 1),
                       "mem_gb": round(torch.cuda.max_memory_allocated() / 2**30, 1)}
                log.append(rec)
                print(json.dumps(rec), flush=True)
        else:
            epoch += 1
            if calib_items:
                m, _ = evaluate_items(model, calib_items, pad_id, yes_ids, no_ids, a.max_tokens, device)
                print(json.dumps({"epoch": epoch, "calib": m}), flush=True)
                log.append({"epoch": epoch, "calib": m})
    minutes = (time.time() - started) / 60

    calib, probs = evaluate_items(model, calib_items, pad_id, yes_ids, no_ids, a.max_tokens, device)
    merged = out / "merged"
    write_merged_lora(model, a.base, merged)
    record = {"base": a.base, "family": "d1", "data": str(a.data), "mode": a.mode, "lr": lr,
              "r": a.r, "alpha": a.alpha, "epochs": a.epochs, "max_steps": a.max_steps,
              "rows_per_step": rows_per_step, "max_tokens": a.max_tokens, "seed": a.seed,
              "train_items": len(train_items), "calib_items": len(calib_items),
              "trainable_params": n_train, "minutes": round(minutes, 1), "log": log,
              "calibration": calib,
              "peak_gb": round(torch.cuda.max_memory_allocated() / 2**30, 1)}
    (out / "train.json").write_text(json.dumps(record, indent=1) + "\n")
    print(json.dumps({k: record[k] for k in ("train_items", "calib_items", "minutes",
                                             "calibration", "peak_gb")}))
    print(f"merged checkpoint: {merged}")


def write_merged_lora(model, base, merged):
    """The base checkpoint with the LoRA deltas folded in (fp32 sum, then
    bf16), written under the base's own tensor names so llama.cpp's d1
    converter reads it like the original."""
    import torch
    from safetensors.torch import load_file, save_file
    merged.mkdir(parents=True, exist_ok=True)
    state = load_file(str(Path(base) / "model.safetensors"))
    deltas = {}
    for name, mod in model.named_modules():
        if hasattr(mod, "lora_A") and "default" in mod.lora_A:
            a_w = mod.lora_A["default"].weight.float()
            b_w = mod.lora_B["default"].weight.float()
            deltas[name] = (mod.scaling["default"] * (b_w @ a_w)).cpu()
    used = 0
    for name, delta in deltas.items():
        # peft names the module base_model.model.<the HF module path>
        key = name.removeprefix("base_model.model.") + ".weight"
        if key not in state:
            raise SystemExit(f"no tensor {key} in the base checkpoint for LoRA module {name}")
        state[key] = (state[key].float() + delta).to(torch.bfloat16)
        used += 1
    save_file(state, str(merged / "model.safetensors"), metadata={"format": "pt"})
    copy_support_files(Path(base), merged)
    print(json.dumps({"merged_modules": used}))


# Everything but the weights, as the model repo ships it (the converter reads
# config.json's auto_map to recognise a d1 checkpoint).
SUPPORT = ["config.json", "tokenizer.json", "tokenizer_config.json", "chat_template.jinja",
           "processor_config.json", "LICENSE", "README.md", "api.py", "hybrid.py", "lfm2_vl.py",
           "modeling_d1.py", "prompt.py", "runner.py"]


def copy_support_files(base, merged):
    import shutil
    for name in SUPPORT:
        if (base / name).is_file():
            shutil.copy2(base / name, merged / name)

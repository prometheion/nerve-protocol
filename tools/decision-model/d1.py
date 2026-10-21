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
    h = h[torch.arange(h.shape[0], device=h.device), last.to(h.device)]
    w = head.weight
    h = h.to(w.device)
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
    with torch.no_grad(), torch.autocast("cuda", dtype=torch.bfloat16, cache_enabled=False):
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

    if a.mode == "full":
        return train_full(a, out, tokenizer, train_items, calib_items, yes_ids, no_ids, pad_id)
    model = AutoModelForImageTextToText.from_pretrained(
        a.base, dtype=torch.bfloat16, attn_implementation="sdpa")
    # Text only: the vision tower and projector are not trained and not needed.
    model.model.vision_tower = None
    model.model.multi_modal_projector = None
    model.to(device)
    model.config.use_cache = False
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    model.enable_input_require_grads()

    from peft import LoraConfig, get_peft_model
    target = r".*language_model.*\.(" + "|".join(LORA_TARGETS) + r")"
    cfg = LoraConfig(r=a.r, lora_alpha=a.alpha, lora_dropout=a.lora_dropout,
                     target_modules=target, bias="none")
    model = get_peft_model(model, cfg)
    trainable = [p for p in model.parameters() if p.requires_grad]
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
                with torch.autocast("cuda", dtype=torch.bfloat16, cache_enabled=False):
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


def token_steps(items, max_tokens, rng):
    """Steps of about `max_tokens` padded tokens each (one backward per step):
    shuffle, sort chunks of 2048 rows by length, cut by the padded size, and
    shuffle the steps."""
    order = list(range(len(items)))
    rng.shuffle(order)
    steps = []
    for c in range(0, len(order), 2048):
        chunk = sorted(order[c:c + 2048], key=lambda i: len(items[i][0]))
        cur = []
        for i in chunk:
            if cur and len(items[i][0]) * (len(cur) + 1) > max_tokens:
                steps.append(cur)
                cur = []
            cur.append(i)
        if cur:
            steps.append(cur)
    rng.shuffle(steps)
    return steps


def train_full(a, out, tokenizer, train_items, calib_items, yes_ids, no_ids, pad_id):
    """Full fine-tuning of the language model on the two 12 GB GPUs.

    The memory is the limit: 2.8B trainable parameters. Every parameter is
    kept in fp32 (the master copy; autocast computes in bf16) with bitsandbytes'
    8-bit AdamW states, 6 bytes per parameter, 17 GB in all; the layers are
    split over the two GPUs (`--split` layers on the first, the rest on the
    second, one micro-batch at a time through both). A parameter's optimizer
    steps in a hook as soon as its gradient is complete, so no gradient is
    held and a step is one forward and backward of `--max-tokens` padded
    tokens (no gradient accumulation, no global clipping). Autocast runs with
    its weight cache off: the cache would hold a bf16 copy of every weight
    (5 GB) until the step ends.
    """
    import torch
    import torch.nn.functional as F
    from accelerate import dispatch_model
    from transformers import AutoModelForImageTextToText
    import bitsandbytes as bnb

    rng = random.Random(a.seed)
    torch.manual_seed(a.seed)
    n_gpu = torch.cuda.device_count()
    if n_gpu < 2:
        raise SystemExit("full fine-tuning of d1-3B needs both GPUs")
    model = AutoModelForImageTextToText.from_pretrained(
        a.base, dtype=torch.bfloat16, attn_implementation="sdpa")
    model.model.vision_tower = None
    model.model.multi_modal_projector = None
    model.config.use_cache = False
    lm = model.model.language_model
    n_layers = len(lm.layers)
    device_map = {"model.language_model.embed_tokens": 0, "model.language_model.rotary_emb": 0,
                  "model.language_model.embedding_norm": 1, "lm_head": 0}
    for i in range(n_layers):
        device_map[f"model.language_model.layers.{i}"] = 0 if i < a.split else 1
    # fp32 on the GPU it lives on, one module at a time (the bf16 copy is 6 GB of RAM).
    for name, dev in device_map.items():
        if name == "lm_head":
            continue
        mod = model.get_submodule(name)
        mod.to(device=f"cuda:{dev}", dtype=torch.float32)
    model.lm_head.weight = lm.embed_tokens.weight
    model = dispatch_model(model, device_map=device_map, main_device="cuda:0",
                           force_hooks=True, skip_keys=["past_key_values"])
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    model.enable_input_require_grads()
    model.train()

    params = [p for p in model.parameters() if p.requires_grad]
    n_train = sum(p.numel() for p in params)
    lr = a.lr
    opts = {p: bnb.optim.AdamW8bit([p], lr=lr, weight_decay=0.01, betas=(0.9, 0.999)) for p in params}

    def step_in_backward(p):
        opts[p].step()
        opts[p].zero_grad(set_to_none=True)

    for p in params:
        p.register_post_accumulate_grad_hook(step_in_backward)
    print(json.dumps({"trainable_params": n_train,
                      "gpu_gb_after_load": [round(torch.cuda.memory_allocated(i) / 2**30, 1)
                                            for i in range(2)]}), flush=True)

    steps_per_epoch = len(token_steps(train_items, a.max_tokens, random.Random(a.seed)))
    total = a.max_steps if a.max_steps > 0 else int(steps_per_epoch * a.epochs)
    warm = max(1, int(0.05 * total))

    def lr_at(step):
        if step < warm:
            return lr * (step + 1) / warm
        return lr * 0.5 * (1 + math.cos(math.pi * (step - warm) / max(1, total - warm)))

    dev0 = torch.device("cuda:0")
    log, step, started, epoch, done = [], 0, time.time(), 0, False
    while not done:
        for st in token_steps(train_items, a.max_tokens, rng):
            if step >= total:
                done = True
                break
            for o in opts.values():
                o.param_groups[0]["lr"] = lr_at(step)
            ids, mask, last, y = collate(st, train_items, pad_id, dev0)
            with torch.autocast("cuda", dtype=torch.bfloat16, cache_enabled=False):
                z = two_way_logits(model, ids, mask, last, yes_ids, no_ids)
            loss = F.cross_entropy(z, y)
            loss.backward()
            step += 1
            if step % 10 == 0 or step == total:
                rec = {"step": step, "of": total, "loss": round(loss.item(), 4), "rows": len(st),
                       "lr": lr_at(step - 1), "min": round((time.time() - started) / 60, 1),
                       "mem_gb": [round(torch.cuda.max_memory_allocated(i) / 2**30, 1) for i in range(2)]}
                log.append(rec)
                print(json.dumps(rec), flush=True)
        else:
            epoch += 1
            if calib_items:
                m, _ = evaluate_items(model, calib_items, pad_id, yes_ids, no_ids, a.max_tokens, dev0)
                print(json.dumps({"epoch": epoch, "calib": m}), flush=True)
                log.append({"epoch": epoch, "calib": m})
    minutes = (time.time() - started) / 60
    calib, _ = evaluate_items(model, calib_items, pad_id, yes_ids, no_ids, a.max_tokens, dev0)
    merged = out / "merged"
    write_full(model, a.base, merged)
    record = {"base": a.base, "family": "d1", "data": str(a.data), "mode": "full", "lr": lr,
              "epochs": a.epochs, "max_steps": a.max_steps, "max_tokens": a.max_tokens,
              "split": a.split, "seed": a.seed, "train_items": len(train_items),
              "calib_items": len(calib_items), "trainable_params": n_train,
              "optimizer": "bitsandbytes AdamW8bit, fp32 weights, step in backward",
              "minutes": round(minutes, 1), "log": log, "calibration": calib,
              "peak_gb": [round(torch.cuda.max_memory_allocated(i) / 2**30, 1) for i in range(2)]}
    (out / "train.json").write_text(json.dumps(record, indent=1) + "\n")
    print(json.dumps({k: record[k] for k in ("train_items", "calib_items", "minutes",
                                             "calibration", "peak_gb")}))
    print(f"merged checkpoint: {merged}")


def write_full(model, base, merged):
    """The trained language model under the base checkpoint's tensor names
    (bf16), the vision tower and projector copied from the base."""
    import torch
    from safetensors.torch import load_file, save_file
    merged.mkdir(parents=True, exist_ok=True)
    state = load_file(str(Path(base) / "model.safetensors"))
    trained = {k: v for k, v in model.state_dict().items() if k != "lm_head.weight"}
    used = 0
    for key in state:
        if key in trained:
            t = trained[key]
            if tuple(t.shape) != tuple(state[key].shape):
                raise SystemExit(f"shape of {key} changed")
            state[key] = t.detach().to("cpu", torch.bfloat16)
            used += 1
        elif "vision_tower" not in key and "multi_modal_projector" not in key:
            raise SystemExit(f"{key} of the base checkpoint is not in the trained model")
    save_file(state, str(merged / "model.safetensors"), metadata={"format": "pt"})
    copy_support_files(Path(base), merged)
    print(json.dumps({"written_tensors": used}))


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

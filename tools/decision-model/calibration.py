"""Temperature scaling of the scores of a decision model, fitted on a dev
split.

The model answers with a probability `p`; scaling its logit by 1/T gives
`sigmoid(logit(p) / T)`. T is the one number that minimises the log loss on
the dev split (T above 1: the model is over-confident). The scaling does not
change the order of the scores, so AUC and the ROC points stay as they were;
it moves the probabilities, and with them the threshold a given
benign-refusal budget leads to. `train.py --calib-cases` fits the same
temperature inside the model (it goes into the GGUF); `compare.py
--calibrate` does it afterwards on the scores of an evaluated run.
"""

import math

EPS = 1e-6


def logit(p):
    p = min(max(p, EPS), 1 - EPS)
    return math.log(p / (1 - p))


def sigmoid(z):
    return 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))


def softplus(x):
    return x + math.log1p(math.exp(-x)) if x > 0 else math.log1p(math.exp(x))


def nll(rows, temperature=1.0):
    """Mean log loss of the rows (`score`, `danger`) at the temperature."""
    total = 0.0
    for r in rows:
        z = logit(r["score"]) / temperature
        total += softplus(-z if r["danger"] else z)
    return total / len(rows)


def ece(rows, temperature=1.0, bins=10):
    """Expected calibration error: the bins' |share dangerous - mean probability|,
    weighted by the number of rows in the bin."""
    cells = [[0, 0.0, 0] for _ in range(bins)]
    for r in rows:
        p = sigmoid(logit(r["score"]) / temperature)
        c = cells[min(int(p * bins), bins - 1)]
        c[0] += 1
        c[1] += p
        c[2] += bool(r["danger"])
    return sum(abs(c[2] - c[1]) for c in cells) / len(rows)


def fit_temperature(rows, low=0.05, high=20.0):
    """The temperature T in [low, high] that minimises the log loss of the
    rows. The loss is convex in 1/T, so a ternary search on that finds it;
    returns 1.0 when a class is missing (nothing to fit)."""
    if not any(r["danger"] for r in rows) or all(r["danger"] for r in rows):
        return 1.0
    lo, hi = 1 / high, 1 / low
    for _ in range(100):
        a, b = lo + (hi - lo) / 3, hi - (hi - lo) / 3
        if nll(rows, 1 / a) < nll(rows, 1 / b):
            hi = b
        else:
            lo = a
    return 1 / ((lo + hi) / 2)


def scale(score, temperature):
    """The score after temperature scaling."""
    return sigmoid(logit(score) / temperature)


def rescored(rows, temperature):
    """The score rows with their scores scaled."""
    return [{**r, "score": scale(r["score"], temperature)} for r in rows]


def raw_threshold(threshold, temperature):
    """The threshold on the unscaled score that equals `threshold` on the
    scaled one (what to configure when the model itself is not rescaled)."""
    return sigmoid(logit(threshold) * temperature)

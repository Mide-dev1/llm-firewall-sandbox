"""
Sweeps the vector-filter similarity threshold across a range of values and
reports precision/recall/F1 at each one, so we can see the real tradeoff
curve instead of guessing a single cutoff.

Embeddings are computed once per example and reused across every threshold
tested -- re-embedding the same 3,598 texts for each candidate threshold
would be wasteful; only the flag decision changes, and that's just a
comparison against a number we already have.

Run after scripts/build_vector_index.py:
    python scripts/tune_threshold.py
"""

from pathlib import Path

import pandas as pd

from firewall.vector_filter import check

DATA_PATH = Path("data/raw/prompt_injections_benchmark.parquet")
HOLDOUT_PATH = Path("data/raw/holdout_attacks.parquet")
THRESHOLDS = [0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75]


def main() -> None:
    df = pd.read_parquet(DATA_PATH)
    holdout_attacks = pd.read_parquet(HOLDOUT_PATH)
    benign = df[df["label"] == "benign"]
    eval_set = pd.concat(
        [holdout_attacks.assign(label="jailbreak"), benign], ignore_index=True
    )

    print(f"Computing similarity scores for {len(eval_set)} examples "
          f"(one pass, reused across all thresholds) ...")

    # threshold=0.0 here is irrelevant to the score itself -- we only read
    # max_similarity and decide flagging ourselves below.
    scored = []
    for i, row in eval_set.iterrows():
        result = check(row["text"], threshold=0.0)
        scored.append((result.max_similarity, row["label"] == "jailbreak"))
        if i % 500 == 0:
            print(f"  ...{i}/{len(eval_set)}")

    print(f"\n{'Threshold':>10} {'TP':>6} {'FP':>6} {'FN':>6} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    for threshold in THRESHOLDS:
        tp = fp = fn = 0
        for similarity, is_attack in scored:
            flagged = similarity >= threshold
            if is_attack and flagged:
                tp += 1
            elif is_attack and not flagged:
                fn += 1
            elif not is_attack and flagged:
                fp += 1

        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * precision * recall / \
            (precision + recall) if (precision + recall) else 0
        print(
            f"{threshold:>10.2f} {tp:>6} {fp:>6} {fn:>6} {precision:>10.3f} {recall:>8.3f} {f1:>8.3f}")


if __name__ == "__main__":
    main()

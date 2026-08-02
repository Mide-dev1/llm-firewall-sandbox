"""
Evaluates the COMBINED pipeline (sanitizer OR vector filter) on the same
held-out set used for the vector filter alone, plus a breakdown of which
layer(s) actually caught each true positive -- this is the number that
justifies having two layers instead of one.

Run after scripts/build_vector_index.py:
    python scripts/evaluate_combined.py
"""

from pathlib import Path

import pandas as pd

from firewall.pipeline import evaluate

DATA_PATH = Path("data/raw/prompt_injections_benchmark.parquet")
HOLDOUT_PATH = Path("data/raw/holdout_attacks.parquet")


def main() -> None:
    df = pd.read_parquet(DATA_PATH)
    holdout_attacks = pd.read_parquet(HOLDOUT_PATH)
    benign = df[df["label"] == "benign"]
    eval_set = pd.concat(
        [holdout_attacks.assign(label="jailbreak"), benign], ignore_index=True
    )

    print(f"Evaluating combined pipeline on {len(eval_set)} examples "
          f"({len(holdout_attacks)} unseen attacks + {len(benign)} benign)\n")

    tp = fp = tn = fn = 0
    caught_by_sanitizer_only = 0
    caught_by_vector_only = 0
    caught_by_both = 0
    missed_by_both: list[str] = []

    for i, row in eval_set.iterrows():
        is_attack = row["label"] == "jailbreak"
        result = evaluate(row["text"])

        if is_attack and result.flagged:
            tp += 1
            if result.sanitizer_flagged and result.vector_flagged:
                caught_by_both += 1
            elif result.sanitizer_flagged:
                caught_by_sanitizer_only += 1
            else:
                caught_by_vector_only += 1
        elif is_attack and not result.flagged:
            fn += 1
            missed_by_both.append(row["text"])
        elif not is_attack and result.flagged:
            fp += 1
        else:
            tn += 1

        if i % 500 == 0:
            print(f"  ...{i}/{len(eval_set)}")

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / \
        (precision + recall) if (precision + recall) else 0

    print(f"\n--- Combined pipeline (sanitizer OR vector) ---")
    print(f"True positives:   {tp}")
    print(f"False positives:  {fp}")
    print(f"True negatives:   {tn}")
    print(f"False negatives:  {fn}")
    print(f"Precision:        {precision:.3f}")
    print(f"Recall:           {recall:.3f}")
    print(f"F1 score:         {f1:.3f}")

    print(f"\n--- Who caught each true positive ---")
    print(f"Sanitizer only:   {caught_by_sanitizer_only}")
    print(f"Vector only:      {caught_by_vector_only}")
    print(f"Both agreed:      {caught_by_both}")

    print(f"\nSample attacks missed by BOTH layers (the real remaining gap):")
    for text in missed_by_both[:5]:
        print(f"  - {text[:100]}...")


if __name__ == "__main__":
    main()

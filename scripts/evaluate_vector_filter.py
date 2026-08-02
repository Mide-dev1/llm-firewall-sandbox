"""
Evaluates the vector-similarity filter honestly: using ONLY held-out
attacks it has never seen (from build_vector_index.py's 30% split) plus
all benign examples. Compare these numbers directly against
evaluate_sanitizer.py's output -- that's your rule-based-vs-vector story.

Run after scripts/build_vector_index.py:
    python scripts/evaluate_vector_filter.py
"""

from pathlib import Path

import pandas as pd

from firewall.vector_filter import check

DATA_PATH = Path("data/raw/prompt_injections_benchmark.parquet")
HOLDOUT_PATH = Path("data/raw/holdout_attacks.parquet")
THRESHOLD = 0.75


def main() -> None:
    df = pd.read_parquet(DATA_PATH)
    holdout_attacks = pd.read_parquet(HOLDOUT_PATH)

    benign = df[df["label"] == "benign"]
    eval_set = pd.concat(
        [holdout_attacks.assign(label="jailbreak"), benign], ignore_index=True
    )

    print(f"Evaluating on {len(holdout_attacks)} held-out (unseen) attacks "
          f"+ {len(benign)} benign examples = {len(eval_set)} total\n")

    true_positive = false_positive = true_negative = false_negative = 0
    missed_attacks: list[str] = []

    for i, row in eval_set.iterrows():
        is_attack = row["label"] == "jailbreak"
        result = check(row["text"], threshold=THRESHOLD)

        if is_attack and result.flagged:
            true_positive += 1
        elif is_attack and not result.flagged:
            false_negative += 1
            missed_attacks.append(row["text"])
        elif not is_attack and result.flagged:
            false_positive += 1
        else:
            true_negative += 1

        if i % 200 == 0:
            print(f"  ...{i}/{len(eval_set)}")

    precision = true_positive / \
        (true_positive + false_positive) if (true_positive + false_positive) else 0
    recall = true_positive / \
        (true_positive + false_negative) if (true_positive + false_negative) else 0
    f1 = 2 * precision * recall / \
        (precision + recall) if (precision + recall) else 0

    print(f"\nThreshold:            {THRESHOLD}")
    print(f"True positives:       {true_positive}")
    print(f"False positives:      {false_positive}")
    print(f"True negatives:       {true_negative}")
    print(f"False negatives:      {false_negative}")
    print(f"Precision:            {precision:.3f}")
    print(f"Recall:               {recall:.3f}")
    print(f"F1 score:             {f1:.3f}")

    print("\nSample missed attacks (unseen, still evaded detection):")
    for text in missed_attacks[:5]:
        print(f"  - {text[:100]}...")


if __name__ == "__main__":
    main()

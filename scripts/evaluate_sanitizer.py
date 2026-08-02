"""
Evaluates the rule-based sanitizer against the downloaded Qualifire dataset
and reports precision/recall/F1, plus a handful of concrete false negatives
(attacks it missed) so we can see exactly what kind of attack it's blind to.

Run after scripts/download_dataset.py:
    python scripts/evaluate_sanitizer.py
"""

from pathlib import Path

import pandas as pd

from firewall.sanitizer import scan

DATA_PATH = Path("data/raw/prompt_injections_benchmark.parquet")


def main() -> None:
    df = pd.read_parquet(DATA_PATH)

    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0
    missed_attacks: list[str] = []

    for _, row in df.iterrows():
        is_attack = row["label"] == "jailbreak"
        flagged = scan(row["text"]).flagged

        if is_attack and flagged:
            true_positive += 1
        elif is_attack and not flagged:
            false_negative += 1
            missed_attacks.append(row["text"])
        elif not is_attack and flagged:
            false_positive += 1
        else:
            true_negative += 1

    precision = true_positive / \
        (true_positive + false_positive) if (true_positive + false_positive) else 0
    recall = true_positive / \
        (true_positive + false_negative) if (true_positive + false_negative) else 0
    f1 = 2 * precision * recall / \
        (precision + recall) if (precision + recall) else 0

    print(f"Total examples:      {len(df)}")
    print(f"True positives:      {true_positive}")
    print(f"False positives:     {false_positive}")
    print(f"True negatives:      {true_negative}")
    print(f"False negatives:     {false_negative}")
    print(f"Precision:           {precision:.3f}")
    print(f"Recall:              {recall:.3f}")
    print(f"F1 score:            {f1:.3f}")

    print("\nSample missed attacks (false negatives) -- these are what the")
    print("vector-similarity layer needs to catch next:")
    for text in missed_attacks[:5]:
        print(f"  - {text[:100]}...")


if __name__ == "__main__":
    main()

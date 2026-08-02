"""
Builds the "known attack" vector database used by firewall.vector_filter.

Splits the jailbreak-labeled examples 70/30:
  - 70% get embedded into the vector database (the "known attacks" we
    compare incoming prompts against)
  - 30% are held out and saved separately -- these are NEVER embedded,
    so they can be used later to honestly test whether the vector filter
    generalizes to attacks it has not seen, instead of just recognizing
    text it was built from.

Run after scripts/download_dataset.py:
    python scripts/build_vector_index.py
"""

from pathlib import Path

import pandas as pd

from firewall.vector_filter import _get_collection, _get_model

DATA_PATH = Path("data/raw/prompt_injections_benchmark.parquet")
HOLDOUT_PATH = Path("data/raw/holdout_attacks.parquet")
BUILD_FRACTION = 0.7


def main() -> None:
    df = pd.read_parquet(DATA_PATH)
    attacks = df[df["label"] == "jailbreak"].sample(
        frac=1, random_state=42)  # shuffle

    split_idx = int(len(attacks) * BUILD_FRACTION)
    build_set = attacks.iloc[:split_idx]
    holdout_set = attacks.iloc[split_idx:]

    print(f"Total attack examples: {len(attacks)}")
    print(f"  -> {len(build_set)} embedded into the known-attack database")
    print(f"  -> {len(holdout_set)} held out for evaluation only")

    holdout_set.to_parquet(HOLDOUT_PATH, index=False)

    print(f"\nLoading embedding model ({_get_model().__class__.__name__}) ...")
    model = _get_model()
    collection = _get_collection()

    texts = build_set["text"].tolist()
    ids = [f"attack-{i}" for i in build_set.index]

    print("Embedding known attacks (this may take a minute on CPU) ...")
    embeddings = model.encode(texts, show_progress_bar=True).tolist()

    collection.add(ids=ids, embeddings=embeddings, documents=texts)

    print(
        f"\nDone. Collection now has {collection.count()} known attack vectors.")


if __name__ == "__main__":
    main()

"""
Downloads the Qualifire prompt injection benchmark dataset from Hugging Face
and saves it locally as a parquet file under data/raw/.

Run manually, once (or whenever you want to refresh the dataset):
    python scripts/download_dataset.py

Requires HF_TOKEN to be set in your .env file (see .env.example).
"""

import os
from pathlib import Path

from datasets import load_dataset
from dotenv import load_dotenv

DATASET_REPO = "rogue-security/prompt-injections-benchmark"
OUTPUT_PATH = Path("data/raw/prompt_injections_benchmark.parquet")


def main() -> None:
    load_dotenv()  # reads .env into environment variables

    token = os.getenv("HF_TOKEN")
    if not token:
        raise RuntimeError(
            "HF_TOKEN not found. Copy .env.example to .env and add your "
            "Hugging Face access token (Settings -> Access Tokens on huggingface.co)."
        )

    print(f"Downloading {DATASET_REPO} ...")

    # load_dataset resolves the repo's actual file layout for us -- we don't
    # need to know or guess the internal file names.
    dataset = load_dataset(DATASET_REPO, token=token)

    # Gated/benchmark datasets are often published with a single split.
    # Grab whichever split exists (commonly "train" or "test") and inspect
    # the rest so nothing is silently dropped.
    split_names = list(dataset.keys())
    print(f"Available splits: {split_names}")
    df = dataset[split_names[0]].to_pandas()

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(OUTPUT_PATH, index=False)

    print(f"Saved {len(df)} rows to {OUTPUT_PATH}")
    print("\nLabel distribution:")
    print(df["label"].value_counts())
    print("\nSample rows:")
    print(df.sample(5, random_state=42))


if __name__ == "__main__":
    main()

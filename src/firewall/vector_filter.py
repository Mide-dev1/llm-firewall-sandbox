"""
Vector-similarity attack detection.

Unlike the regex sanitizer, this layer doesn't look for exact phrases --
it embeds incoming text into a numeric vector ("embedding") that captures
its *meaning*, then compares it against a database of known-attack
embeddings. If the incoming prompt is semantically close to something we've
seen before -- even with totally different wording -- it gets flagged.

This is the same core idea as antivirus heuristic detection, just operating
in embedding space instead of on file bytes.
"""

from pathlib import Path

import chromadb
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

# small, fast, good enough for a portfolio-scale project
MODEL_NAME = "all-MiniLM-L6-v2"
CHROMA_PATH = str(Path("data/chroma_db"))
COLLECTION_NAME = "known_attacks"

_model: SentenceTransformer | None = None
_client: chromadb.ClientAPI | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def _get_collection():
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(path=CHROMA_PATH)
    # hnsw:space="cosine" tells Chroma to use cosine similarity, the
    # standard choice for sentence-embedding comparisons.
    return _client.get_or_create_collection(
        COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
    )


class VectorFilterResult(BaseModel):
    flagged: bool
    max_similarity: float
    nearest_attack_text: str | None


def check(text: str, threshold: float = 0.55) -> VectorFilterResult:
    """
    Embed `text` and compare it to the nearest known attack in the vector
    database. threshold is a cosine similarity cutoff between 0 (unrelated)
    and 1 (identical meaning).

    0.55 was chosen empirically via a threshold sweep (see
    scripts/tune_threshold.py) as the best F1 tradeoff (precision 0.506,
    recall 0.700) on a held-out set of unseen attacks. This layer is not
    the system's only defense -- it feeds into the quarantined/privileged
    LLM split -- so it's tuned for balanced F1 rather than maximum recall.
    """
    model = _get_model()
    collection = _get_collection()

    embedding = model.encode(text).tolist()
    results = collection.query(query_embeddings=[embedding], n_results=1)

    distances = results["distances"][0]
    if not distances:
        return VectorFilterResult(flagged=False, max_similarity=0.0, nearest_attack_text=None)

    # Chroma returns cosine *distance* (0 = identical); similarity is the inverse.
    similarity = 1 - distances[0]
    nearest_text = results["documents"][0][0]

    return VectorFilterResult(
        flagged=similarity >= threshold,
        max_similarity=similarity,
        nearest_attack_text=nearest_text,
    )

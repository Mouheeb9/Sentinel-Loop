"""Local text embeddings (ONNX via fastembed — no PyTorch, no remote model code).

Jina v2 base: 768 dims, 8,192-token window. The longest chunk in the corpus is ~1,500
tokens, so nothing is truncated (a 512-token model would cut roughly half the ATT&CK
technique chunks). Queries and documents use the same call: this model needs no prefix.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import numpy as np
from fastembed import TextEmbedding

MODEL_NAME = "jinaai/jina-embeddings-v2-base-en"
DIM = 768
# fastembed defaults to the system temp dir, which Windows clears — keep the 0.5 GB model here.
MODEL_CACHE = Path(__file__).resolve().parents[3] / "data" / "raw" / "models"


@lru_cache(maxsize=1)
def _model() -> TextEmbedding:
    return TextEmbedding(MODEL_NAME, cache_dir=str(MODEL_CACHE))


def embed_texts(texts: list[str], batch_size: int = 16) -> list[np.ndarray]:
    return list(_model().embed(texts, batch_size=batch_size))

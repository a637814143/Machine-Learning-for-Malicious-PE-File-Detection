"""Self-contained feature extraction and vectorisation helpers.

This package vendors a minimal subset of the project's original feature
pipeline so that the standalone Flask service can load ``model.txt`` and
produce predictions without importing modules from the repository root.
"""

from .static_features import extract_features
from .vectorization import vectorize_features, VECTOR_SIZE

__all__ = ["extract_features", "vectorize_features", "VECTOR_SIZE"]

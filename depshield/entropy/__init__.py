"""Information-theory engine for obfuscation detection."""
from depshield.entropy.shannon import shannon_entropy, entropy_category
from depshield.entropy.compression import compression_ratio
from depshield.entropy.ngram import bigram_entropy, trigram_entropy, ngram_uniformity
from depshield.entropy.charclass import char_class_distribution, char_class_entropy

__all__ = [
    "shannon_entropy",
    "entropy_category",
    "compression_ratio",
    "bigram_entropy",
    "trigram_entropy",
    "ngram_uniformity",
    "char_class_distribution",
    "char_class_entropy",
]

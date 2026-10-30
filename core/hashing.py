"""
Hashing and entropy analysis module for static document triage.
Calculates cryptographic digests and Shannon entropy without executing code.
"""

import math
import hashlib
from typing import Dict, Union
from pathlib import Path


def calculate_hashes(data_or_path: Union[bytes, str, Path]) -> Dict[str, str]:
    """
    Calculate SHA-256, SHA-1, and MD5 hashes for raw bytes or a file path.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    if isinstance(data_or_path, (str, Path)):
        file_path = Path(data_or_path)
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)
    elif isinstance(data_or_path, bytes):
        sha256.update(data_or_path)
        sha1.update(data_or_path)
        md5.update(data_or_path)
    else:
        raise TypeError(f"Expected bytes or file path, got {type(data_or_path).__name__}")

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence.
    Returns a float between 0.0 and 8.0 bits per byte.
    """
    if not data:
        return 0.0

    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p_i = count / length
            entropy -= p_i * math.log2(p_i)

    return round(entropy, 4)

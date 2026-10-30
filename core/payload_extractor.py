"""
Payload Extraction Module.
Statically recovers embedded binary payloads, hex-encoded buffers, byte arrays,
and candidate shellcode sequences without executing them.
"""

import re
import binascii
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from core.hashing import calculate_hashes, shannon_entropy
from core.vba_extractor import VBAExtractionResult


@dataclass
class ExtractedPayload:
    """Structured representation of an extracted binary payload."""
    payload_id: str
    source_document: str
    source_module: str
    source_line: Optional[int]
    payload_size: int
    sha256: str
    entropy: float
    raw_bytes: bytes
    extraction_method: str  # "VBA_BYTE_ARRAY", "HEX_BUFFER", "BASE64_STREAM", "DEOBFUSCATION"
    extraction_status: str  # "RECOVERED", "TRUNCATED", "FAILED"
    supporting_evidence: str
    limitations: List[str] = field(default_factory=list)


class PayloadExtractor:
    """Statically identifies and extracts binary payloads from VBA code modules."""

    # Matches VBA byte arrays: Array(77, 90, 144, 0, 3, ...) or Array(&H4D, &H5A, ...)
    BYTE_ARRAY_PATTERN = re.compile(r"Array\s*\(\s*([0-9a-fA-F&Hh,\s]{20,})\s*\)", re.IGNORECASE)

    # Matches contiguous hex literal strings: "4D5A90000300..."
    HEX_LITERAL_PATTERN = re.compile(r'"([0-9a-fA-F]{32,})"')

    @classmethod
    def _parse_byte_tokens(cls, tokens_str: str) -> Optional[bytes]:
        """Convert comma-separated VBA numeric/hex tokens to bytes."""
        parts = [p.strip() for p in tokens_str.split(",") if p.strip()]
        byte_list = []
        for p in parts:
            try:
                if p.lower().startswith("&h"):
                    val = int(p[2:], 16)
                else:
                    val = int(p)
                if 0 <= val <= 255:
                    byte_list.append(val)
                else:
                    return None
            except ValueError:
                return None
        return bytes(byte_list) if byte_list else None

    @classmethod
    def extract_from_code(cls, code: str, module_name: str, doc_name: str) -> List[ExtractedPayload]:
        """Extract payloads from VBA code text."""
        payloads: List[ExtractedPayload] = []
        counter = 1
        lines = code.splitlines()

        for idx, line in enumerate(lines, start=1):
            # Check 1: Array(...) byte sequences
            for match in cls.BYTE_ARRAY_PATTERN.finditer(line):
                tokens_str = match.group(1)
                parsed_bytes = cls._parse_byte_tokens(tokens_str)
                if parsed_bytes and len(parsed_bytes) >= 8:
                    h = calculate_hashes(parsed_bytes)["sha256"]
                    ent = shannon_entropy(parsed_bytes)
                    payloads.append(ExtractedPayload(
                        payload_id=f"PAYLOAD_{module_name}_{counter}",
                        source_document=doc_name,
                        source_module=module_name,
                        source_line=idx,
                        payload_size=len(parsed_bytes),
                        sha256=h,
                        entropy=ent,
                        raw_bytes=parsed_bytes,
                        extraction_method="VBA_BYTE_ARRAY",
                        extraction_status="RECOVERED",
                        supporting_evidence=line.strip()[:100],
                        limitations=["Extracted statically from VBA Array() declaration."]
                    ))
                    counter += 1

            # Check 2: Contiguous Hex literals
            for match in cls.HEX_LITERAL_PATTERN.finditer(line):
                hex_str = match.group(1)
                if len(hex_str) % 2 == 0 and len(hex_str) >= 32:
                    try:
                        raw = bytes.fromhex(hex_str)
                        h = calculate_hashes(raw)["sha256"]
                        ent = shannon_entropy(raw)
                        payloads.append(ExtractedPayload(
                            payload_id=f"PAYLOAD_{module_name}_{counter}",
                            source_document=doc_name,
                            source_module=module_name,
                            source_line=idx,
                            payload_size=len(raw),
                            sha256=h,
                            entropy=ent,
                            raw_bytes=raw,
                            extraction_method="HEX_BUFFER",
                            extraction_status="RECOVERED",
                            supporting_evidence=line.strip()[:100],
                            limitations=["Extracted statically from long hexadecimal literal."]
                        ))
                        counter += 1
                    except Exception:
                        pass

        return payloads

    @classmethod
    def extract_all(cls, vba_result: VBAExtractionResult, doc_name: str) -> List[ExtractedPayload]:
        """Extract all payloads across all modules."""
        all_payloads: List[ExtractedPayload] = []
        for mod in vba_result.modules:
            all_payloads.extend(cls.extract_from_code(mod.code, mod.module_name, doc_name))
        return all_payloads

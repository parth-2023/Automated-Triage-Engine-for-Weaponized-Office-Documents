"""
Payload Extraction Module.

Statically recovers embedded binary payloads, hex-encoded buffers, byte arrays,
and candidate shellcode sequences without executing them.

Data flow:
  VBA source modules  → extract_from_code()   (original text patterns)
  DeobfuscationResult → extract_from_deobf()  (reconstructed strings and buffers)

Every extracted candidate records:
  - source_module, source_line, extraction_method
  - byte length, SHA-256, entropy
  - extraction_status (RECOVERED / TRUNCATED / FAILED)
  - confidence (High / Medium / Low)
  - is_payload_candidate: True if it looks like binary data, False if it is a decoded string

Security: extracted bytes are never executed or written to disk.
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from core.hashing import calculate_hashes, shannon_entropy
from core.vba_extractor import VBAExtractionResult

# Import at runtime to avoid circular imports
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from core.deobfuscator import DeobfuscationResult

MAX_PAYLOAD_BYTES = 10 * 1024 * 1024   # 10 MB hard limit per candidate


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
    extraction_method: str       # "VBA_BYTE_ARRAY", "HEX_BUFFER", "BASE64_STREAM",
                                 # "DEOBF_BASE64", "DEOBF_HEX", "DEOBF_XOR"
    extraction_status: str       # "RECOVERED", "TRUNCATED", "FAILED"
    supporting_evidence: str
    confidence: str = "High"     # "High", "Medium", "Low"
    is_payload_candidate: bool = True   # False for decoded strings that are not binary
    limitations: List[str] = field(default_factory=list)


class PayloadExtractor:
    """Statically identifies and extracts binary payloads from VBA code modules."""

    # Matches VBA byte arrays: Array(77, 90, 144, 0, 3, ...) or Array(&H4D, &H5A, ...)
    BYTE_ARRAY_PATTERN = re.compile(r"Array\s*\(\s*([0-9a-fA-F&Hh,\s]{20,})\s*\)", re.IGNORECASE)

    # Matches contiguous hex literal strings: "4D5A90..."  (>= 32 hex chars = 16 bytes)
    HEX_LITERAL_PATTERN = re.compile(r'"([0-9a-fA-F]{32,})"')

    # Magic byte signatures for common binary types
    _MAGIC_SIGNATURES = {
        b"MZ": "PE Executable (DOS MZ header)",
        b"PK": "ZIP / Office OpenXML archive",
        b"\x7fELF": "ELF Executable",
        b"\xd0\xcf\x11\xe0": "OLE2 Compound Document",
        b"\x4d\x5a\x90": "PE Executable",
        b"\xff\xd8\xff": "JPEG image",
        b"\x89PNG": "PNG image",
    }

    @classmethod
    def _parse_byte_tokens(cls, tokens_str: str) -> Optional[bytes]:
        """Convert comma-separated VBA numeric/hex tokens to bytes."""
        parts = [p.strip() for p in tokens_str.split(",") if p.strip()]
        if len(parts) > MAX_PAYLOAD_BYTES:
            return None
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
    def _classify_bytes(cls, data: bytes) -> Tuple_confidence_candidate:
        """Return (is_payload_candidate, confidence) based on byte content."""
        # Check known magic bytes
        for magic, _ in cls._MAGIC_SIGNATURES.items():
            if data[:len(magic)] == magic:
                return True, "High"
        # High entropy suggests binary / encrypted data
        ent = shannon_entropy(data)
        if ent > 6.5:
            return True, "Medium"
        if len(data) >= 64:
            return True, "Low"
        return False, "Low"

    @classmethod
    def extract_from_code(cls, code: str, module_name: str, doc_name: str) -> List[ExtractedPayload]:
        """Extract payloads from VBA code text (static patterns)."""
        payloads: List[ExtractedPayload] = []
        counter = 1
        lines = code.splitlines()

        for idx, line in enumerate(lines, start=1):
            # Check 1: Array(...) byte sequences
            for match in cls.BYTE_ARRAY_PATTERN.finditer(line):
                tokens_str = match.group(1)
                parsed_bytes = cls._parse_byte_tokens(tokens_str)
                if parsed_bytes and len(parsed_bytes) >= 8:
                    if len(parsed_bytes) > MAX_PAYLOAD_BYTES:
                        continue
                    h = calculate_hashes(parsed_bytes)["sha256"]
                    ent = shannon_entropy(parsed_bytes)
                    is_cand, conf = cls._classify_bytes(parsed_bytes)
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
                        confidence=conf,
                        is_payload_candidate=is_cand,
                        limitations=["Extracted statically from VBA Array() declaration."],
                    ))
                    counter += 1

            # Check 2: Contiguous Hex literals
            for match in cls.HEX_LITERAL_PATTERN.finditer(line):
                hex_str = match.group(1)
                if len(hex_str) % 2 == 0 and len(hex_str) >= 32:
                    try:
                        raw = bytes.fromhex(hex_str)
                        if len(raw) > MAX_PAYLOAD_BYTES:
                            continue
                        h = calculate_hashes(raw)["sha256"]
                        ent = shannon_entropy(raw)
                        is_cand, conf = cls._classify_bytes(raw)
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
                            confidence=conf,
                            is_payload_candidate=is_cand,
                            limitations=["Extracted statically from long hexadecimal literal."],
                        ))
                        counter += 1
                    except Exception:
                        pass

        return payloads

    @classmethod
    def extract_from_deobf(
        cls,
        deobf_results: List["DeobfuscationResult"],
        doc_name: str,
    ) -> List[ExtractedPayload]:
        """
        Extract binary payload candidates from deobfuscation results.

        Consumes structured DeobfuscationResult objects and attempts to
        decode their reconstructed_value as binary data where appropriate.
        """
        payloads: List[ExtractedPayload] = []
        counter = 1
        seen_hashes = set()

        for d in deobf_results:
            if not d.is_complete:
                continue   # skip partial/uncertain results

            raw: Optional[bytes] = None
            method = "DEOBF_UNKNOWN"

            if d.transformation_type == "BASE64":
                try:
                    import base64 as _b64
                    raw = _b64.b64decode(d.original_expression, validate=True)
                    method = "DEOBF_BASE64"
                except Exception:
                    # original_expression might not be the raw b64 string in all cases
                    pass

            elif d.transformation_type == "HEX_DECODE":
                try:
                    hex_str = d.original_expression.strip()
                    if len(hex_str) % 2 == 0:
                        raw = bytes.fromhex(hex_str)
                        method = "DEOBF_HEX"
                except Exception:
                    pass

            elif d.transformation_type == "XOR_DECRYPT":
                # We only record XOR loops as evidence (cannot reconstruct without running)
                continue

            if raw is None or len(raw) < 8:
                continue
            if len(raw) > MAX_PAYLOAD_BYTES:
                continue

            h = calculate_hashes(raw)["sha256"]
            if h in seen_hashes:
                continue
            seen_hashes.add(h)

            ent = shannon_entropy(raw)
            is_cand, conf = cls._classify_bytes(raw)

            payloads.append(ExtractedPayload(
                payload_id=f"DEOBF_{d.source_module}_{counter}",
                source_document=doc_name,
                source_module=d.source_module,
                source_line=d.line_number,
                payload_size=len(raw),
                sha256=h,
                entropy=ent,
                raw_bytes=raw,
                extraction_method=method,
                extraction_status="RECOVERED",
                supporting_evidence=d.original_expression[:100],
                confidence=conf,
                is_payload_candidate=is_cand,
                limitations=["Extracted from deobfuscation output; authenticity not independently verified."],
            ))
            counter += 1

        return payloads

    @classmethod
    def extract_all(
        cls,
        vba_result: VBAExtractionResult,
        doc_name: str,
        deobf_results: Optional[List] = None,
    ) -> List[ExtractedPayload]:
        """Extract all payloads across all modules and deobfuscation results."""
        all_payloads: List[ExtractedPayload] = []

        # From raw VBA source
        for mod in vba_result.modules:
            all_payloads.extend(cls.extract_from_code(mod.code, mod.module_name, doc_name))

        # From deobfuscation output (connected pipeline)
        if deobf_results:
            all_payloads.extend(cls.extract_from_deobf(deobf_results, doc_name))

        # Deduplicate by SHA-256
        seen = set()
        deduped = []
        for p in all_payloads:
            if p.sha256 not in seen:
                seen.add(p.sha256)
                deduped.append(p)

        return deduped


# Type hint helper
from typing import Tuple as Tuple_confidence_candidate

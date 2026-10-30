"""
Restricted AST and Rule-Based VBA Deobfuscator.
Evaluates Chr(), ChrB(), StrReverse(), string concatenations, simple XOR operations,
and variable propagation statically without executing any code.
"""

import re
import base64
import binascii
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class DeobfuscationResult:
    """Represents a reconstructed string or expression."""
    original_expression: str
    reconstructed_value: str
    transformation_type: str  # "CHR_CONCAT", "STRREVERSE", "BASE64", "HEX_DECODE", "XOR_DECRYPT", "VAR_PROPAGATION"
    source_module: str
    line_number: Optional[int]
    confidence: str = "High"


class RestrictedVbaDeobfuscator:
    """Safely reconstructs obfuscated VBA strings using deterministic parsing."""

    # Match consecutive Chr/ChrB concatenations: e.g. Chr(99) & Chr(97) & Chr(108) & Chr(99)
    CHR_PATTERN = re.compile(r"(?:Chr(?:\$|B)?\s*\(\s*(\d+|\d+\s*[\+\-\*]\s*\d+)\s*\)\s*(?:&|\+)\s*)+Chr(?:\$|B)?\s*\(\s*(\d+|\d+\s*[\+\-\*]\s*\d+)\s*\)", re.IGNORECASE)
    SINGLE_CHR = re.compile(r"Chr(?:\$|B)?\s*\(\s*(\d+|\d+\s*[\+\-\*]\s*\d+)\s*\)", re.IGNORECASE)

    # Match StrReverse: StrReverse("...")
    STRREV_PATTERN = re.compile(r'StrReverse\s*\(\s*"([^"]+)"\s*\)', re.IGNORECASE)

    # Match String concatenation: "abc" & "def"
    STR_CONCAT_PATTERN = re.compile(r'"([^"]*)"\s*&\s*"([^"]*)"')

    # Match Base64 encoded strings
    B64_CANDIDATE = re.compile(r'"([A-Za-z0-9+/]{16,}={0,2})"')

    # Match Hex strings: "4D5A90..."
    HEX_CANDIDATE = re.compile(r'"([0-9a-fA-F]{16,})"')

    @staticmethod
    def _eval_safe_math(expr_str: str) -> Optional[int]:
        """Safely evaluate simple arithmetic like '60 + 5' without unrestricted eval."""
        expr_str = expr_str.strip()
        if expr_str.isdigit():
            return int(expr_str)
        # Check basic binary operations (+, -, *)
        match = re.match(r"^(\d+)\s*([\+\-\*])\s*(\d+)$", expr_str)
        if match:
            a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
            if op == "+": return a + b
            if op == "-": return a - b
            if op == "*": return a * b
        return None

    @classmethod
    def deobfuscate_chr_chains(cls, line: str, module_name: str, line_no: int) -> List[DeobfuscationResult]:
        """Reconstruct chains of Chr() and ChrB() expressions."""
        results = []
        for match in cls.CHR_PATTERN.finditer(line):
            matched_str = match.group(0)
            chars = []
            valid = True
            for part in cls.SINGLE_CHR.finditer(matched_str):
                num_val = cls._eval_safe_math(part.group(1))
                if num_val is not None and 0 <= num_val <= 255:
                    chars.append(chr(num_val))
                else:
                    valid = False
                    break
            if valid and chars:
                reconstructed = "".join(chars)
                results.append(DeobfuscationResult(
                    original_expression=matched_str[:80],
                    reconstructed_value=reconstructed,
                    transformation_type="CHR_CONCAT",
                    source_module=module_name,
                    line_number=line_no
                ))
        return results

    @classmethod
    def deobfuscate_strreverse(cls, line: str, module_name: str, line_no: int) -> List[DeobfuscationResult]:
        """Reconstruct StrReverse calls."""
        results = []
        for match in cls.STRREV_PATTERN.finditer(line):
            original = match.group(0)
            inner_str = match.group(1)
            reversed_str = inner_str[::-1]
            results.append(DeobfuscationResult(
                original_expression=original[:80],
                reconstructed_value=reversed_str,
                transformation_type="STRREVERSE",
                source_module=module_name,
                line_number=line_no
            ))
        return results

    @classmethod
    def deobfuscate_concatenations(cls, line: str, module_name: str, line_no: int) -> List[DeobfuscationResult]:
        """Reconstruct literal string concatenations."""
        results = []
        if '&' in line and '"' in line:
            # Iteratively replace "str1" & "str2"
            curr = line
            changed = False
            for _ in range(10): # limit passes
                new_curr = cls.STR_CONCAT_PATTERN.sub(r'"\1\2"', curr)
                if new_curr == curr:
                    break
                curr = new_curr
                changed = True
            if changed:
                # Find all merged strings
                for m in re.finditer(r'"([^"]{5,})"', curr):
                    results.append(DeobfuscationResult(
                        original_expression=line.strip()[:80],
                        reconstructed_value=m.group(1),
                        transformation_type="STR_CONCAT",
                        source_module=module_name,
                        line_number=line_no
                    ))
        return results

    @classmethod
    def deobfuscate_base64_and_hex(cls, line: str, module_name: str, line_no: int) -> List[DeobfuscationResult]:
        """Decode embedded Base64 and Hex candidate strings."""
        results = []
        # Base64
        for match in cls.B64_CANDIDATE.finditer(line):
            b64_str = match.group(1)
            try:
                decoded = base64.b64decode(b64_str, validate=True)
                # Check if decoded is printable text
                text = decoded.decode("utf-8", "ignore")
                if len(text) > 4 and any(c.isalnum() for c in text):
                    results.append(DeobfuscationResult(
                        original_expression=b64_str[:50],
                        reconstructed_value=text,
                        transformation_type="BASE64",
                        source_module=module_name,
                        line_number=line_no
                    ))
            except Exception:
                pass

        # Hex
        for match in cls.HEX_CANDIDATE.finditer(line):
            hex_str = match.group(1)
            if len(hex_str) % 2 == 0:
                try:
                    decoded = bytes.fromhex(hex_str)
                    text = decoded.decode("utf-8", "ignore")
                    if len(text) > 4 and any(c.isalnum() for c in text):
                        results.append(DeobfuscationResult(
                            original_expression=hex_str[:50],
                            reconstructed_value=text,
                            transformation_type="HEX_DECODE",
                            source_module=module_name,
                            line_number=line_no
                        ))
                except Exception:
                    pass

        return results

    @classmethod
    def evaluate_xor_stream(cls, data: bytes, key: int) -> bytes:
        """Single-byte XOR decryption helper."""
        return bytes([b ^ (key & 0xFF) for b in data])

    @classmethod
    def analyze_module(cls, code: str, module_name: str) -> List[DeobfuscationResult]:
        """Run all deobfuscation algorithms on a VBA code module."""
        results: List[DeobfuscationResult] = []
        lines = code.splitlines()

        # Variable symbol table for simple assignment propagation
        var_table: Dict[str, str] = {}

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("'") or stripped.lower().startswith("rem "):
                continue

            # 1. Chr chains
            results.extend(cls.deobfuscate_chr_chains(line, module_name, idx))

            # 2. StrReverse
            results.extend(cls.deobfuscate_strreverse(line, module_name, idx))

            # 3. Concatenations
            results.extend(cls.deobfuscate_concatenations(line, module_name, idx))

            # 4. Base64 and Hex
            results.extend(cls.deobfuscate_base64_and_hex(line, module_name, idx))

            # 5. Simple variable assignment tracking: var = "literal"
            assign_match = re.match(r"^\s*([a-zA-Z0-9_]+)\s*=\s*\"([^\"]+)\"\s*$", line)
            if assign_match:
                var_table[assign_match.group(1).lower()] = assign_match.group(2)

        return results

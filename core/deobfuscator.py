"""
Restricted AST and Rule-Based VBA Deobfuscator.

Supported transformations (deterministic, no eval/exec):
  - Chr() / ChrB() / Chr$() concatenation chains
  - StrReverse("literal") calls
  - String literal concatenation with & operator
  - Constant propagation (simple variable assignments)
  - Base64-encoded string literals
  - Hexadecimal string literals
  - Single-byte XOR stream helper
  - Simple, bounded single-byte XOR loop patterns

Security invariants:
  - Never uses Python eval() or exec()
  - Never executes VBA, shell commands, or any payload
  - All loops are bounded by MAX_LOOP_ITER
  - Decoded output is bounded by MAX_DECODED_BYTES
  - Recursion is bounded by MAX_RECURSION_DEPTH
  - Processing is stateless; no file I/O

Each result records:
  - original_expression : the source text
  - reconstructed_value : the decoded string (or bytes hex for binary buffers)
  - transformation_type : method used
  - is_complete         : whether reconstruction is complete or partial
  - confidence          : High / Medium / Low
  - source_module / line_number
"""

import re
import base64
import binascii
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


# ---------------------------------------------------------------------------
# Safety limits
# ---------------------------------------------------------------------------

MAX_LOOP_ITER    = 1024        # maximum iterations when emulating a loop
MAX_DECODED_BYTES = 65536      # maximum decoded output bytes
MAX_EXPR_LEN     = 4096        # maximum expression string length to process
MAX_RECURSION    = 4           # maximum variable substitution depth


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class DeobfuscationResult:
    """Represents a reconstructed string or expression."""
    original_expression: str
    reconstructed_value: str
    transformation_type: str   # "CHR_CONCAT", "STRREVERSE", "STR_CONCAT",
                               # "BASE64", "HEX_DECODE", "XOR_DECRYPT", "VAR_PROPAGATION"
    source_module: str
    line_number: Optional[int]
    confidence: str = "High"
    is_complete: bool = True   # False if reconstruction was partial or uncertain
    note: str = ""             # explanation when incomplete or low-confidence
    raw_bytes: Optional[bytes] = None  # Decoded binary payload bytes if applicable


# ---------------------------------------------------------------------------
# Deobfuscator
# ---------------------------------------------------------------------------

class RestrictedVbaDeobfuscator:
    """Safely reconstructs obfuscated VBA strings using deterministic parsing."""

    # Match consecutive Chr/ChrB concatenations: e.g. Chr(99) & Chr(97) & Chr(108) & Chr(99)
    CHR_PATTERN = re.compile(
        r"(?:Chr(?:\$|B)?\s*\(\s*(\d+|\d+\s*[\+\-\*]\s*\d+)\s*\)\s*(?:&|\+)\s*)+Chr(?:\$|B)?\s*\(\s*(\d+|\d+\s*[\+\-\*]\s*\d+)\s*\)",
        re.IGNORECASE
    )
    SINGLE_CHR = re.compile(r"Chr(?:\$|B)?\s*\(\s*(\d+|\d+\s*[\+\-\*]\s*\d+)\s*\)", re.IGNORECASE)

    # Match StrReverse("...") — only with literal string argument
    STRREV_PATTERN = re.compile(r'StrReverse\s*\(\s*"([^"]+)"\s*\)', re.IGNORECASE)

    # Match literal string concatenation: "abc" & "def"
    STR_CONCAT_PATTERN = re.compile(r'"([^"]*)"\s*&\s*"([^"]*)"')

    # Base64 candidate: a quoted string of only valid base64 characters, length >= 16
    B64_CANDIDATE = re.compile(r'"([A-Za-z0-9+/]{16,}={0,2})"')

    # Hex candidate: a quoted string of only hex characters, length >= 32, even length
    HEX_CANDIDATE = re.compile(r'"([0-9a-fA-F]{32,})"')

    # Simple XOR loop: For i = 0 To N : buf(i) = buf(i) Xor KEY : Next i
    XOR_LOOP_PATTERN = re.compile(
        r"For\s+\w+\s*=\s*0\s+To\s+(\d+)\s*[:\n]"
        r".*?\w+\s*\(\s*\w+\s*\)\s*=\s*\w+\s*\(\s*\w+\s*\)\s+[Xx][Oo][Rr]\s+(\d+)",
        re.IGNORECASE | re.DOTALL
    )

    # Simple variable assignment: varname = "literal"
    ASSIGN_LITERAL = re.compile(r"^\s*([a-zA-Z_]\w*)\s*=\s*\"([^\"]+)\"\s*$")

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _eval_safe_math(expr_str: str) -> Optional[int]:
        """Safely evaluate simple arithmetic (no eval). Supports +, -, * on two integers."""
        expr_str = expr_str.strip()
        if expr_str.isdigit():
            return int(expr_str)
        match = re.match(r"^(\d+)\s*([\+\-\*])\s*(\d+)$", expr_str)
        if match:
            a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
            if op == "+": return a + b
            if op == "-": return a - b
            if op == "*": return a * b
        return None

    # String literal token matching (including escaped double quotes "")
    QUOTED_STRING_TOKEN = re.compile(r'("(?:[^"]|"")*")')

    @classmethod
    def _substitute_vars(cls, text: str, var_table: Dict[str, str], depth: int = 0) -> str:
        """
        Replace variable references with their known string values (bounded depth).
        String-aware token substitution: NEVER replaces variable names inside quoted literals.
        """
        if depth >= MAX_RECURSION or len(text) > MAX_EXPR_LEN or not var_table:
            return text

        changed = True
        result = text
        iterations = 0

        while changed and iterations < 20:
            changed = False
            iterations += 1

            # Split line into quoted string literals and non-quoted code segments
            # Even-indexed segments are code; odd-indexed segments are string literals
            segments = cls.QUOTED_STRING_TOKEN.split(result)

            for var_name, var_val in var_table.items():
                var_pattern = re.compile(r'\b' + re.escape(var_name) + r'\b', re.IGNORECASE)
                escaped_val = var_val.replace('"', '""')
                replacement = f'"{escaped_val}"'

                for i in range(0, len(segments), 2):
                    code_seg = segments[i]
                    new_seg = var_pattern.sub(replacement, code_seg)
                    if new_seg != code_seg:
                        segments[i] = new_seg
                        changed = True

            result = "".join(segments)
            if len(result) > MAX_EXPR_LEN:
                break

        return result

    # -------------------------------------------------------------------------
    # Public transformation methods
    # -------------------------------------------------------------------------

    @classmethod
    def deobfuscate_chr_chains(cls, line: str, module_name: str, line_no: int) -> List[DeobfuscationResult]:
        """Reconstruct chains of Chr() and ChrB() expressions."""
        if len(line) > MAX_EXPR_LEN:
            return []
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
                    line_number=line_no,
                    confidence="High",
                    is_complete=True,
                ))
            elif chars:
                # Partial reconstruction
                reconstructed = "".join(chars)
                results.append(DeobfuscationResult(
                    original_expression=matched_str[:80],
                    reconstructed_value=reconstructed,
                    transformation_type="CHR_CONCAT",
                    source_module=module_name,
                    line_number=line_no,
                    confidence="Low",
                    is_complete=False,
                    note="One or more Chr() arguments could not be evaluated.",
                ))
        return results

    @classmethod
    def deobfuscate_strreverse(cls, line: str, module_name: str, line_no: int) -> List[DeobfuscationResult]:
        """Reconstruct StrReverse calls with literal string arguments."""
        if len(line) > MAX_EXPR_LEN:
            return []
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
                line_number=line_no,
                confidence="High",
                is_complete=True,
            ))
        return results

    @classmethod
    def deobfuscate_concatenations(cls, line: str, module_name: str, line_no: int) -> List[DeobfuscationResult]:
        """Reconstruct literal string concatenations with &."""
        if len(line) > MAX_EXPR_LEN:
            return []
        results = []
        if '&' in line and '"' in line:
            curr = line
            changed = False
            for _ in range(10):   # limit passes
                new_curr = cls.STR_CONCAT_PATTERN.sub(r'"\1\2"', curr)
                if new_curr == curr:
                    break
                curr = new_curr
                changed = True
            if changed:
                for m in re.finditer(r'"([^"]{5,})"', curr):
                    val = m.group(1)
                    if len(val) <= MAX_DECODED_BYTES:
                        results.append(DeobfuscationResult(
                            original_expression=line.strip()[:80],
                            reconstructed_value=val,
                            transformation_type="STR_CONCAT",
                            source_module=module_name,
                            line_number=line_no,
                            confidence="High",
                            is_complete=True,
                        ))
        return results

    @classmethod
    def deobfuscate_base64_and_hex(cls, line: str, module_name: str, line_no: int) -> List[DeobfuscationResult]:
        """Decode embedded Base64 and Hex candidate strings."""
        if len(line) > MAX_EXPR_LEN:
            return []
        results = []

        # Base64
        for match in cls.B64_CANDIDATE.finditer(line):
            b64_str = match.group(1)
            try:
                decoded = base64.b64decode(b64_str, validate=True)
                if len(decoded) > MAX_DECODED_BYTES:
                    continue
                text = decoded.decode("utf-8", "ignore")
                if len(text) > 4 and any(c.isalnum() for c in text):
                    results.append(DeobfuscationResult(
                        original_expression=b64_str[:50],
                        reconstructed_value=text,
                        transformation_type="BASE64",
                        source_module=module_name,
                        line_number=line_no,
                        confidence="Medium",   # base64 candidates may be false positives
                        is_complete=True,
                        raw_bytes=decoded,
                    ))
            except Exception:
                pass

        # Hex
        for match in cls.HEX_CANDIDATE.finditer(line):
            hex_str = match.group(1)
            if len(hex_str) % 2 == 0:
                try:
                    decoded = bytes.fromhex(hex_str)
                    if len(decoded) > MAX_DECODED_BYTES:
                        continue
                    text = decoded.decode("utf-8", "ignore")
                    if len(text) > 4 and any(c.isalnum() for c in text):
                        results.append(DeobfuscationResult(
                            original_expression=hex_str[:50],
                            reconstructed_value=text,
                            transformation_type="HEX_DECODE",
                            source_module=module_name,
                            line_number=line_no,
                            confidence="Medium",
                            is_complete=True,
                            raw_bytes=decoded,
                        ))
                except Exception:
                    pass

        return results

    @classmethod
    def evaluate_xor_stream(cls, data: bytes, key: int) -> bytes:
        """
        Single-byte XOR decryption helper.
        Input data is bounded by MAX_DECODED_BYTES.
        """
        if len(data) > MAX_DECODED_BYTES:
            raise ValueError(f"Data exceeds MAX_DECODED_BYTES ({MAX_DECODED_BYTES})")
        return bytes([b ^ (key & 0xFF) for b in data])

    # Variable assignment: varname = <expr>
    ASSIGN_ANY = re.compile(r"^\s*(?:Set\s+|Let\s+)?([a-zA-Z_]\w*)\s*=\s*(.+)$", re.IGNORECASE)
    BYTE_ARRAY_PATTERN = re.compile(r"Array\s*\(\s*([0-9a-fA-F&Hh,\s]{10,})\s*\)", re.IGNORECASE)

    @classmethod
    def _parse_numeric_tokens(cls, tokens_str: str) -> Optional[bytes]:
        """Convert comma-separated VBA numeric/hex tokens to bytes."""
        parts = [p.strip() for p in tokens_str.split(",") if p.strip()]
        if len(parts) > MAX_DECODED_BYTES:
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
    def _evaluate_assignment_rhs(cls, rhs: str, var_table: Dict[str, str]) -> Optional[str]:
        """Safely evaluate simple string assignments (constants, Chr, StrReverse, concat)."""
        rhs = rhs.strip()
        # Literal string: "hello"
        if rhs.startswith('"') and rhs.endswith('"') and rhs.count('"') == 2:
            return rhs[1:-1]

        # StrReverse("...")
        strrev = cls.STRREV_PATTERN.match(rhs)
        if strrev:
            return strrev.group(1)[::-1]

        # Chr chains: Chr(65) & Chr(66)
        if "chr" in rhs.lower():
            chr_res = cls.deobfuscate_chr_chains(rhs, "eval", 0)
            if chr_res and chr_res[0].is_complete:
                return chr_res[0].reconstructed_value

        # Variable substitution & concat: var1 & "suffix"
        if "&" in rhs:
            substituted = cls._substitute_vars(rhs, var_table)
            concat_res = cls.deobfuscate_concatenations(substituted, "eval", 0)
            if concat_res:
                return concat_res[0].reconstructed_value

        # Direct variable copy: var2 = var1
        if rhs.lower() in var_table:
            return var_table[rhs.lower()]

        return None

    @classmethod
    def detect_xor_loop(
        cls,
        code_block: str,
        module_name: str,
        line_no: int,
        byte_table: Optional[Dict[str, bytes]] = None
    ) -> List[DeobfuscationResult]:
        """
        Detect and safely evaluate bounded XOR loops when target buffer is statically known.
        Never executes live code; uses bounded mathematical byte transformation.
        """
        results = []
        byte_table = byte_table or {}

        # Loop matching buffer variable name: For i = 0 To N : buf(i) = buf(i) Xor KEY : Next i
        detailed_xor = re.compile(
            r"For\s+\w+\s*=\s*0\s+To\s+(\d+)\s*[:\n]"
            r".*?([a-zA-Z_]\w*)\s*\(\s*\w+\s*\)\s*=\s*\2\s*\(\s*\w+\s*\)\s+[Xx][Oo][Rr]\s+(\d+)",
            re.IGNORECASE | re.DOTALL
        )

        for match in detailed_xor.finditer(code_block):
            iteration_count = int(match.group(1))
            buf_name = match.group(2).lower()
            xor_key = int(match.group(3))

            if iteration_count > MAX_LOOP_ITER:
                results.append(DeobfuscationResult(
                    original_expression=match.group(0)[:80],
                    reconstructed_value=f"[XOR_LOOP_OVERSIZED: iterations={iteration_count+1}]",
                    transformation_type="XOR_DECRYPT",
                    source_module=module_name,
                    line_number=line_no,
                    confidence="Low",
                    is_complete=False,
                    note=f"XOR loop exceeds MAX_LOOP_ITER ({MAX_LOOP_ITER}); not reconstructed.",
                ))
                continue

            # If the buffer is known from static assignments, safely evaluate!
            if buf_name in byte_table:
                known_bytes = byte_table[buf_name]
                eval_len = min(iteration_count + 1, len(known_bytes))
                target_slice = known_bytes[:eval_len]
                try:
                    decrypted = cls.evaluate_xor_stream(target_slice, xor_key)
                    text_preview = decrypted.decode("utf-8", "ignore")
                    results.append(DeobfuscationResult(
                        original_expression=match.group(0)[:80],
                        reconstructed_value=text_preview if any(c.isalnum() for c in text_preview) else f"<Binary Buffer: {len(decrypted)} bytes>",
                        transformation_type="XOR_DECRYPT",
                        source_module=module_name,
                        line_number=line_no,
                        confidence="High",
                        is_complete=True,
                        raw_bytes=decrypted,
                        note=f"Safely evaluated bounded XOR loop on statically known buffer '{buf_name}' (key=0x{xor_key:02X})."
                    ))
                    continue
                except Exception:
                    pass

            # Otherwise, record as evidence with is_complete=False
            results.append(DeobfuscationResult(
                original_expression=match.group(0)[:80],
                reconstructed_value=f"[XOR_LOOP: key=0x{xor_key:02X}, iterations={iteration_count+1}]",
                transformation_type="XOR_DECRYPT",
                source_module=module_name,
                line_number=line_no,
                confidence="Medium",
                is_complete=False,
                note=f"XOR loop detected (key=0x{xor_key:02X}). Target buffer '{buf_name}' not statically resolved.",
            ))

        return results

    @classmethod
    def analyze_module(cls, code: str, module_name: str) -> List[DeobfuscationResult]:
        """Run all deobfuscation algorithms on a VBA code module."""
        results: List[DeobfuscationResult] = []
        lines = code.splitlines()

        # Variable symbol tables
        var_table: Dict[str, str] = {}
        byte_table: Dict[str, bytes] = {}

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("'") or stripped.lower().startswith("rem "):
                continue

            # Substitute known variables before analysis
            expanded_line = cls._substitute_vars(line, var_table) if var_table else line

            # 1. Chr chains
            results.extend(cls.deobfuscate_chr_chains(expanded_line, module_name, idx))

            # 2. StrReverse
            results.extend(cls.deobfuscate_strreverse(expanded_line, module_name, idx))

            # 3. Concatenations
            results.extend(cls.deobfuscate_concatenations(expanded_line, module_name, idx))

            # 4. Base64 and Hex
            results.extend(cls.deobfuscate_base64_and_hex(expanded_line, module_name, idx))

            # 5. Variable assignment tracking (constants, expressions, byte arrays)
            assign_match = cls.ASSIGN_ANY.match(line)
            if assign_match:
                vname = assign_match.group(1).lower()
                rhs = assign_match.group(2).strip()

                # Check if RHS is a byte array: buf = Array(...)
                arr_match = cls.BYTE_ARRAY_PATTERN.search(rhs)
                if arr_match:
                    parsed = cls._parse_numeric_tokens(arr_match.group(1))
                    if parsed:
                        byte_table[vname] = parsed

                # Evaluate string expression
                val = cls._evaluate_assignment_rhs(rhs, var_table)
                if val is not None and len(val) <= MAX_DECODED_BYTES:
                    var_table[vname] = val

        # 6. Whole-module XOR loop detection & safe evaluation
        results.extend(cls.detect_xor_loop(code, module_name, 0, byte_table=byte_table))

        return results

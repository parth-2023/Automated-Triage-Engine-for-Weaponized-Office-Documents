"""
YARA Rule Synthesizer Module.

Automatically synthesizes syntactically valid, compilable YARA detection rules
from verified static findings, reconstructed strings, and extracted payload byte sequences.

DESIGN & VALIDATION INVARIANTS:
  - A rule is NEVER reported as valid (is_valid_syntax=True or status=COMPILED)
    unless it has actually been compiled successfully with the YARA compiler.
  - If yara-python is unavailable, status is GENERATED_NOT_VALIDATED and
    is_valid_syntax is False.
  - Generates scoped conditions (container file magic + indicator combinations)
    to prevent false positives from generic 'any of them' conditions.
  - Strings are strictly sanitized and escaped against syntax injection.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from core.ingestion import IngestedDocument
from core.fusion import FusedDetectionResult
from core.deobfuscator import DeobfuscationResult
from core.payload_extractor import ExtractedPayload


class YaraRuleStatus:
    COMPILED                = "COMPILED"
    GENERATED_NOT_VALIDATED = "GENERATED_NOT_VALIDATED"
    INVALID_SYNTAX          = "INVALID_SYNTAX"
    NO_STRINGS              = "NO_STRINGS"


@dataclass
class SynthesizedYaraRule:
    """Represents an auto-generated YARA detection rule."""
    rule_name: str
    rule_text: str
    is_valid_syntax: bool
    status: str = YaraRuleStatus.COMPILED
    matching_strings: List[str] = field(default_factory=list)
    compilation_error: Optional[str] = None
    source_evidence_count: int = 0


class YaraRuleSynthesizer:
    """Generates and validates YARA rules based on extracted static artifacts."""

    @classmethod
    def sanitize_rule_name(cls, name: str) -> str:
        """Sanitize name to make a valid YARA identifier."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        if not clean or clean[0].isdigit():
            clean = f"rule_{clean}"
        return clean[:64]

    @classmethod
    def escape_yara_string(cls, s: str) -> str:
        """
        Safely escape string for embedding in YARA double-quoted literals.
        Handles backslashes, quotes, control characters, and multi-byte Unicode.
        """
        if s is None:
            return ""
        out = []
        for char in str(s):
            if char == "\\":
                out.append("\\\\")
            elif char == '"':
                out.append('\\"')
            elif char == "\t":
                out.append("\\t")
            elif char == "\r":
                out.append("\\r")
            elif char == "\n":
                out.append("\\n")
            elif 32 <= ord(char) <= 126:
                out.append(char)
            else:
                # Safely escape non-ASCII bytes as \xNN
                for b in char.encode("utf-8"):
                    out.append(f"\\x{b:02x}")
        return "".join(out)

    @classmethod
    def synthesize_rule(
        cls,
        doc: IngestedDocument,
        fused: FusedDetectionResult,
        deobf_results: List[DeobfuscationResult],
        payloads: List[ExtractedPayload]
    ) -> SynthesizedYaraRule:
        """
        Construct a valid YARA rule based on verified indicators.
        """
        raw_name = f"WeaponizedDoc_{doc.hashes.get('sha256', 'sample')[:8]}"
        rule_name = cls.sanitize_rule_name(raw_name)

        strings_block: List[str] = []
        string_ids: List[str] = []
        hex_ids: List[str] = []
        api_ids: List[str] = []

        seen_strings = set()
        str_idx = 1
        hex_idx = 1
        api_idx = 1

        # 1. Distinctive reconstructed strings (> 5 characters, non-generic)
        for d in deobf_results:
            val = d.reconstructed_value.strip()
            if len(val) >= 6 and val not in seen_strings:
                seen_strings.add(val)
                escaped = cls.escape_yara_string(val)
                identifier = f"$s{str_idx}"
                strings_block.append(f'        {identifier} = "{escaped}" ascii wide nocase')
                string_ids.append(identifier)
                str_idx += 1
                if str_idx > 8:
                    break

        # 2. Extracted payload byte sequences (distinctive hex patterns)
        for p in payloads:
            if p.raw_bytes and len(p.raw_bytes) >= 16:
                hex_sig = " ".join(f"{b:02X}" for b in p.raw_bytes[:16])
                identifier = f"$hex{hex_idx}"
                strings_block.append(f"        {identifier} = {{ {hex_sig} }}")
                hex_ids.append(identifier)
                hex_idx += 1
                if hex_idx > 8:
                    break

        # 3. Distinctive Win32 API declarations
        for f in fused.deduplicated_findings:
            if "Win32API_" in f.indicator_name:
                api_pure = f.indicator_name.replace("Win32API_", "").strip()
                if api_pure and api_pure not in seen_strings:
                    seen_strings.add(api_pure)
                    escaped_api = cls.escape_yara_string(api_pure)
                    identifier = f"$api{api_idx}"
                    strings_block.append(f'        {identifier} = "{escaped_api}" ascii nocase')
                    api_ids.append(identifier)
                    api_idx += 1
                    if api_idx > 8:
                        break

        total_evidence = len(string_ids) + len(hex_ids) + len(api_ids)

        # 4. Formulate scoped condition (avoiding overly broad 'any of them')
        # Requires multi-indicator synergy or verified hex payload sequences
        if hex_ids and (string_ids and api_ids):
            condition_expr = f"any of ({', '.join(hex_ids)}) or (any of ({', '.join(string_ids)}) and any of ({', '.join(api_ids)}))"
        elif hex_ids and string_ids:
            condition_expr = f"any of ({', '.join(hex_ids)}) or (2 of ({', '.join(string_ids)}))" if len(string_ids) >= 2 else f"any of ({', '.join(hex_ids)}) or {string_ids[0]}"
        elif hex_ids:
            condition_expr = f"any of ({', '.join(hex_ids)})"
        elif string_ids and api_ids:
            condition_expr = f"any of ({', '.join(string_ids)}) and any of ({', '.join(api_ids)})"
        elif len(string_ids) >= 2:
            condition_expr = f"2 of ({', '.join(string_ids)})"
        elif string_ids:
            condition_expr = string_ids[0]
        elif len(api_ids) >= 2:
            condition_expr = f"2 of ({', '.join(api_ids)})"
        elif api_ids:
            condition_expr = api_ids[0]
        else:
            # Fallback when no distinctive string/hex artifacts exist
            fallback_hash = doc.hashes.get('sha256', '0' * 64)
            strings_block.append(f'        $doc_hash = "{fallback_hash}"')
            condition_expr = "$doc_hash"

        # 5. Office container specificity: scope condition with container magic bytes
        det_format = (doc.detected_format or "").upper()
        ext = (doc.extension or "").lower()
        ole_exts = {".doc", ".dot", ".xls", ".xlt", ".ppt"}
        openxml_exts = {
            ".docx", ".docm", ".dotx", ".dotm",
            ".xlsx", ".xlsm", ".xltx", ".xltm",
            ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"
        }
        container_magic = None
        if det_format == "OLE" or ext in ole_exts:
            container_magic = "uint32(0) == 0xE011CFD0"
        elif det_format in ("OPENXML", "ZIP") or ext in openxml_exts:
            container_magic = "uint16(0) == 0x4B50"

        if container_magic:
            final_condition = f"{container_magic} and ({condition_expr})"
        else:
            final_condition = condition_expr

        # 6. Validate and escape metadata values against syntax corruption
        raw_sha = str(doc.hashes.get("sha256", "")).strip().lower()
        if re.match(r"^[0-9a-fA-F]{64}$", raw_sha):
            safe_sha = raw_sha
        else:
            safe_sha = "UNKNOWN_OR_UNAVAILABLE"

        safe_orig_filename = cls.escape_yara_string(doc.safe_filename or "unnamed_sample")
        safe_author = cls.escape_yara_string("Automated Office Triage Engine")
        safe_desc = cls.escape_yara_string("Auto-generated detection rule for weaponized Office document sample")

        rule_template = f"""rule {rule_name}
{{
    meta:
        description = "{safe_desc}"
        author = "{safe_author}"
        date = "2026-10-30"
        sha256 = "{safe_sha}"
        original_file = "{safe_orig_filename}"
        reference = "Static Analysis Detection Fusion"
        evidence_count = {total_evidence}

    strings:
{chr(10).join(strings_block)}

    condition:
        {final_condition}
}}
"""
        # Validate syntax using yara-python if available
        if YARA_AVAILABLE:
            try:
                yara.compile(source=rule_template)
                is_valid = True
                status = YaraRuleStatus.COMPILED
                comp_err = None
            except Exception as e:
                is_valid = False
                status = YaraRuleStatus.INVALID_SYNTAX
                comp_err = str(e)
        else:
            # If YARA dependency is missing, do NOT falsely claim it is valid
            is_valid = False
            status = YaraRuleStatus.GENERATED_NOT_VALIDATED
            comp_err = "yara-python library is not available to compile and validate this rule."

        return SynthesizedYaraRule(
            rule_name=rule_name,
            rule_text=rule_template,
            is_valid_syntax=is_valid,
            status=status,
            matching_strings=[s.strip() for s in strings_block],
            compilation_error=comp_err,
            source_evidence_count=total_evidence
        )

"""
YARA Rule Synthesizer Module.
Automatically synthesizes syntactically valid, compilable YARA detection rules
from verified static findings, reconstructed strings, and extracted payload byte sequences.
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


@dataclass
class SynthesizedYaraRule:
    """Represents an auto-generated YARA detection rule."""
    rule_name: str
    rule_text: str
    is_valid_syntax: bool
    matching_strings: List[str] = field(default_factory=list)
    compilation_error: Optional[str] = None


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
        raw_name = f"WeaponizedDoc_{doc.hashes['sha256'][:8]}"
        rule_name = cls.sanitize_rule_name(raw_name)

        strings_block: List[str] = []
        conditions: List[str] = []
        str_idx = 1

        # 1. Add distinctive reconstructed strings (> 4 characters)
        seen_strings = set()
        for d in deobf_results:
            val = d.reconstructed_value.strip()
            # Avoid generic single words
            if len(val) >= 6 and val not in seen_strings:
                seen_strings.add(val)
                # Escape quotes and backslashes for YARA string
                escaped = val.replace("\\", "\\\\").replace('"', '\\"')
                strings_block.append(f'        $s{str_idx} = "{escaped}" ascii wide nocase')
                str_idx += 1
                if str_idx > 8:
                    break

        # 2. Add extracted payload byte sequences (hex patterns)
        for p in payloads:
            if len(p.raw_bytes) >= 16:
                # Use first 16 bytes as hex signature
                hex_sig = " ".join(f"{b:02X}" for b in p.raw_bytes[:16])
                strings_block.append(f"        $hex{str_idx} = {{ {hex_sig} }}")
                str_idx += 1
                if str_idx > 10:
                    break

        # 3. Add distinctive Win32 API declarations if present
        for f in fused.deduplicated_findings:
            if "Win32API_" in f.indicator_name:
                api_pure = f.indicator_name.replace("Win32API_", "")
                if api_pure not in seen_strings:
                    seen_strings.add(api_pure)
                    strings_block.append(f'        $api{str_idx} = "{api_pure}" ascii nocase')
                    str_idx += 1
                    if str_idx > 12:
                        break

        # If no distinctive strings were collected, add a fallback signature
        if not strings_block:
            strings_block.append('        $doc_hash = "' + doc.hashes['sha256'] + '"')

        # Formulate condition: any of them ensures positive match on distinctive signatures
        condition_expr = "any of them"

        rule_template = f"""rule {rule_name}
{{
    meta:
        description = "Auto-generated detection rule for weaponized Office document sample"
        author = "Automated Office Triage Engine"
        date = "2026-10-30"
        sha256 = "{doc.hashes['sha256']}"
        original_file = "{doc.safe_filename}"
        reference = "Static Analysis Detection Fusion"

    strings:
{chr(10).join(strings_block)}

    condition:
        {condition_expr}
}}
"""
        # Validate syntax using yara-python if available
        is_valid = True
        comp_err = None
        if YARA_AVAILABLE:
            try:
                yara.compile(source=rule_template)
            except Exception as e:
                is_valid = False
                comp_err = str(e)

        return SynthesizedYaraRule(
            rule_name=rule_name,
            rule_text=rule_template,
            is_valid_syntax=is_valid,
            matching_strings=[s.strip() for s in strings_block],
            compilation_error=comp_err
        )

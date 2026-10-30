"""
VBA Stomping Detection Module.
Disassembles compiled P-code tokens using pcodedmp and compares them against
extracted readable VBA source code to compute the Stomping Discrepancy Index (SDI).
"""

import io
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from argparse import Namespace

try:
    import pcodedmp.pcodedmp as pcode_engine
    PCODEDMP_AVAILABLE = True
except ImportError:
    PCODEDMP_AVAILABLE = False

from core.vba_extractor import VBAExtractionResult, VBAModule


@dataclass
class StompingDiscrepancy:
    """Specific semantic divergence between VBA source and P-code instructions."""
    discrepancy_type: str  # "MISSING_SOURCE_CALL", "SOURCE_PCODE_MISMATCH", "UNREFERENCED_PCODE_STRING"
    module_name: str
    pcode_token: str
    explanation: str
    severity: str = "HIGH"


@dataclass
class StompingAnalysisResult:
    """Complete VBA Stomping analysis result."""
    is_stomped: bool
    sdi_score: float  # Stomping Discrepancy Index [0.0 - 1.0]
    pcode_token_count: int
    source_line_count: int
    pcode_disassembly: str
    discrepancies: List[StompingDiscrepancy] = field(default_factory=list)
    analysis_status: str = "COMPLETED"  # "COMPLETED", "PARTIAL", "UNSUPPORTED", "NOT_PERFORMED"
    notes: List[str] = field(default_factory=list)


class StompingDetector:
    """Detects VBA Stomping through differential P-code vs Source analysis."""

    @classmethod
    def analyze(cls, file_path: Path, vba_result: VBAExtractionResult) -> StompingAnalysisResult:
        """
        Disassemble P-code using pcodedmp and correlate with VBA source lines.
        """
        if not PCODEDMP_AVAILABLE:
            return StompingAnalysisResult(
                is_stomped=False,
                sdi_score=0.0,
                pcode_token_count=0,
                source_line_count=vba_result.total_line_count,
                pcode_disassembly="",
                analysis_status="PARTIAL",
                notes=["pcodedmp is not available in the current environment."]
            )

        if not vba_result.has_macros:
            return StompingAnalysisResult(
                is_stomped=False,
                sdi_score=0.0,
                pcode_token_count=0,
                source_line_count=0,
                pcode_disassembly="",
                analysis_status="NOT_PERFORMED",
                notes=["No VBA macros present to analyze for stomping."]
            )

        # Run pcodedmp disassembler safely
        out_stream = io.StringIO()
        args = Namespace(raw=False, verbose=False, dump=False, buffer=False, disasm=True)
        try:
            pcode_engine.processFile(str(file_path), args, output_file=out_stream)
            pcode_text = out_stream.getvalue()
        except Exception as e:
            return StompingAnalysisResult(
                is_stomped=False,
                sdi_score=0.0,
                pcode_token_count=0,
                source_line_count=vba_result.total_line_count,
                pcode_disassembly="",
                analysis_status="PARTIAL",
                notes=[f"P-code extraction encountered error: {str(e)}"]
            )

        # Parse disassembly tokens
        pcode_lines = pcode_text.splitlines()
        pcode_token_count = len([l for l in pcode_lines if l.strip() and not l.startswith("Processing file:")])

        # Extract identifiers, function calls, and strings from P-code
        pcode_calls = set(re.findall(r"\b(?:Call|LitVarSpecial|ArgsLd|ArgsMemLd)\s+([a-zA-Z0-9_]+)", pcode_text, re.IGNORECASE))
        pcode_strings = set(re.findall(r'LitStr\s*:\s*"([^"]+)"', pcode_text, re.IGNORECASE))

        # Extract identifiers and strings from readable source code
        combined_source = "\n".join(m.code for m in vba_result.modules)
        source_strings = set(re.findall(r'"([^"]*)"', combined_source))
        source_lower = combined_source.lower()

        discrepancies: List[StompingDiscrepancy] = []

        # Check 1: P-code calls missing from readable source
        for call in pcode_calls:
            if call.lower() not in source_lower:
                discrepancies.append(StompingDiscrepancy(
                    discrepancy_type="MISSING_SOURCE_CALL",
                    module_name="PCodeStream",
                    pcode_token=call,
                    explanation=f"P-code invokes '{call}' which is absent from VBA source code. Source may have been stomped."
                ))

        # Check 2: Strings present in P-code but absent in VBA source
        for s in pcode_strings:
            if s and s not in source_strings and len(s) > 3:
                discrepancies.append(StompingDiscrepancy(
                    discrepancy_type="UNREFERENCED_PCODE_STRING",
                    module_name="PCodeStream",
                    pcode_token=s[:50],
                    explanation=f"String literal '{s[:30]}' exists in compiled P-code but not in VBA source."
                ))

        # Calculate Stomping Discrepancy Index (SDI)
        # SDI version 1: weighted count of unrepresented calls and strings relative to token count
        if pcode_token_count > 0:
            call_mismatches = len([d for d in discrepancies if d.discrepancy_type == "MISSING_SOURCE_CALL"])
            str_mismatches = len([d for d in discrepancies if d.discrepancy_type == "UNREFERENCED_PCODE_STRING"])
            # Weight function call divergence higher than string variations
            divergence_weight = (call_mismatches * 0.25) + (str_mismatches * 0.1)
            sdi = min(1.0, round(divergence_weight, 4))
        else:
            sdi = 0.0

        is_stomped = sdi >= 0.25 or any(d.discrepancy_type == "MISSING_SOURCE_CALL" for d in discrepancies)

        return StompingAnalysisResult(
            is_stomped=is_stomped,
            sdi_score=sdi,
            pcode_token_count=pcode_token_count,
            source_line_count=vba_result.total_line_count,
            pcode_disassembly=pcode_text[:5000] if len(pcode_text) > 5000 else pcode_text,
            discrepancies=discrepancies,
            analysis_status="COMPLETED",
            notes=[f"Analyzed {pcode_token_count} P-code tokens across {len(vba_result.modules)} modules."]
        )

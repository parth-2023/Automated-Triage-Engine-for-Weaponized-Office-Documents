"""
VBA Stomping Detection Module.

Disassembles compiled P-code tokens using pcodedmp and performs semantic differential
analysis against extracted readable VBA source code to compute the heuristic
Stomping Discrepancy Index (SDI).

DESIGN & LIMITATIONS NOTE:
  - SDI is a HEURISTIC divergence index between 0.0 and 1.0, not a statistically
    validated probability.
  - A difference in token counts alone is never used as proof of VBA stomping.
  - The analysis explicitly compares semantic constructs:
      1. Declared procedures (Subs / Functions) present in P-code vs Source.
      2. Procedure/API calls (ArgsLd, ArgsMemLd, Call, LitVarSpecial) present in P-code vs Source.
      3. String literals (LitStr) present in P-code vs Source.
  - If compiled P-code cannot be extracted or disassembled, the analysis returns
    PARTIAL or UNAVAILABLE rather than fabricating a zero discrepancy.
"""

import io
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
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
    discrepancy_type: str  # "MISSING_SOURCE_CALL", "MISSING_SOURCE_PROC", "UNREFERENCED_PCODE_STRING"
    module_name: str
    pcode_token: str
    explanation: str
    severity: str = "HIGH"  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    confidence: str = "High"


@dataclass
class StompingAnalysisResult:
    """Complete VBA Stomping analysis result."""
    is_stomped: bool
    sdi_score: float  # Heuristic Stomping Discrepancy Index [0.0 - 1.0]
    pcode_token_count: int
    source_line_count: int
    pcode_disassembly: str
    discrepancies: List[StompingDiscrepancy] = field(default_factory=list)
    analysis_status: str = "COMPLETED"  # "COMPLETED", "PARTIAL", "FAILED", "NOT_PERFORMED", "UNAVAILABLE"
    confidence: str = "Medium"  # "High", "Medium", "Low"
    notes: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


class StompingDetector:
    """Detects VBA Stomping through differential P-code vs Source analysis."""

    # High-risk functions that strongly suggest stomped weaponization when hidden
    HIGH_RISK_INVOCATIONS = {
        "shell", "virtualalloc", "virtualallocex", "rtlmovememory", "writeprocessmemory",
        "createthread", "createremotethread", "urldownloadtofile", "urldownloadtofilea",
        "winexec", "shellexecute", "wscript.shell", "powershell", "cmd.exe"
    }

    @classmethod
    def _extract_source_constructs(cls, source_code: str) -> Dict[str, Any]:
        """Extract declared procedures, calls, and strings from VBA source code."""
        # Procedures
        proc_pattern = re.compile(
            r"^\s*(?:Public\s+|Private\s+|Friend\s+)?(?:Static\s+)?(Sub|Function|Property\s+\w+)\s+([a-zA-Z0-9_]+)",
            re.IGNORECASE | re.MULTILINE
        )
        procedures = {m.group(2).lower() for m in proc_pattern.finditer(source_code)}

        # Calls and identifiers (word tokens)
        source_words = set(re.findall(r"\b[a-zA-Z_]\w*\b", source_code.lower()))

        # String literals
        source_strings = set(re.findall(r'"([^"]*)"', source_code))

        return {
            "procedures": procedures,
            "words": source_words,
            "strings": source_strings,
        }

    @classmethod
    def _parse_pcode_disassembly(cls, pcode_text: str) -> Dict[str, Any]:
        """Extract procedures, function calls, and string literals from pcodedmp disassembly."""
        pcode_lines = pcode_text.splitlines()
        token_count = len([l for l in pcode_lines if l.strip() and not l.startswith("Processing")])

        # Declared procedures in P-code (e.g. "ProcDef: Sub ...", "Begin Proc: ...", or "Tag: Sub ...")
        proc_matches = set(re.findall(r"(?:ProcDef|Begin Proc|ProcHeader)\s*[:\s]\s*(?:Sub|Function)?\s*([a-zA-Z0-9_]+)", pcode_text, re.IGNORECASE))

        # Calls in P-code (ArgsLd, ArgsMemLd, Call, LitVarSpecial)
        call_matches = set(re.findall(r"\b(?:Call|LitVarSpecial|ArgsLd|ArgsMemLd)\s+([a-zA-Z0-9_]+)", pcode_text, re.IGNORECASE))

        # String literals (LitStr: "...")
        string_matches = set(re.findall(r'LitStr\s*:\s*"([^"]+)"', pcode_text, re.IGNORECASE))

        return {
            "token_count": token_count,
            "procedures": proc_matches,
            "calls": call_matches,
            "strings": string_matches,
        }

    @classmethod
    def compare_pcode_to_source(
        cls,
        pcode_data: Dict[str, Any],
        source_data: Dict[str, Any],
        module_name: str = "PCodeStream"
    ) -> List[StompingDiscrepancy]:
        """
        Compare semantic elements extracted from P-code against source elements.
        """
        discrepancies: List[StompingDiscrepancy] = []

        # 1. P-code calls missing from source text
        for call in pcode_data["calls"]:
            call_lower = call.lower()
            if call_lower not in source_data["words"]:
                # High-risk call missing is CRITICAL
                is_high_risk = call_lower in cls.HIGH_RISK_INVOCATIONS
                severity = "CRITICAL" if is_high_risk else "HIGH"
                conf = "High" if is_high_risk else "Medium"
                discrepancies.append(StompingDiscrepancy(
                    discrepancy_type="MISSING_SOURCE_CALL",
                    module_name=module_name,
                    pcode_token=call,
                    explanation=(
                        f"P-code invokes '{call}' which does not appear anywhere in readable VBA source code. "
                        f"{'HIGH-RISK INVOCATION: indicates stomped weaponization.' if is_high_risk else 'Indicates potential VBA stomping.'}"
                    ),
                    severity=severity,
                    confidence=conf
                ))

        # 2. Declared procedures in P-code missing from source code
        for proc in pcode_data["procedures"]:
            if proc.lower() not in source_data["procedures"]:
                discrepancies.append(StompingDiscrepancy(
                    discrepancy_type="MISSING_SOURCE_PROC",
                    module_name=module_name,
                    pcode_token=proc,
                    explanation=f"Compiled procedure '{proc}' exists in P-code but is not declared in VBA source code.",
                    severity="HIGH",
                    confidence="High"
                ))

        # 3. String literals present in P-code but absent in VBA source
        for s in pcode_data["strings"]:
            if s and s not in source_data["strings"] and len(s) > 3:
                # Filter out pure compiler-internal strings if any
                discrepancies.append(StompingDiscrepancy(
                    discrepancy_type="UNREFERENCED_PCODE_STRING",
                    module_name=module_name,
                    pcode_token=s[:50],
                    explanation=f"String literal '{s[:30]}' exists in compiled P-code but is absent in VBA source.",
                    severity="MEDIUM",
                    confidence="Medium"
                ))

        return discrepancies

    @classmethod
    def evaluate_discrepancies(
        cls,
        discrepancies: List[StompingDiscrepancy],
        pcode_token_count: int,
        source_line_count: int,
        pcode_text: str = "",
    ) -> StompingAnalysisResult:
        """Calculate documented heuristic SDI score and final verdict."""
        call_mismatches = [d for d in discrepancies if d.discrepancy_type == "MISSING_SOURCE_CALL"]
        proc_mismatches = [d for d in discrepancies if d.discrepancy_type == "MISSING_SOURCE_PROC"]
        str_mismatches = [d for d in discrepancies if d.discrepancy_type == "UNREFERENCED_PCODE_STRING"]

        has_critical_call = any(d.severity == "CRITICAL" for d in call_mismatches)

        # Documented heuristic SDI formula:
        # SDI = min(1.0, 0.40 * proc_count + 0.30 * call_count + 0.10 * str_count)
        # Any critical invocation (e.g. Shell, VirtualAlloc) immediately sets SDI >= 0.80.
        if has_critical_call:
            sdi = 0.90
            is_stomped = True
            confidence = "High"
        elif call_mismatches or proc_mismatches:
            divergence = (len(proc_mismatches) * 0.40) + (len(call_mismatches) * 0.30) + (len(str_mismatches) * 0.10)
            sdi = min(1.0, round(divergence, 4))
            is_stomped = sdi >= 0.30
            confidence = "High" if len(proc_mismatches) > 0 else "Medium"
        elif str_mismatches:
            divergence = len(str_mismatches) * 0.10
            sdi = min(1.0, round(divergence, 4))
            is_stomped = sdi >= 0.40
            confidence = "Low"
        else:
            sdi = 0.0
            is_stomped = False
            confidence = "High"

        return StompingAnalysisResult(
            is_stomped=is_stomped,
            sdi_score=sdi,
            pcode_token_count=pcode_token_count,
            source_line_count=source_line_count,
            pcode_disassembly=pcode_text[:2000],
            discrepancies=discrepancies,
            analysis_status="COMPLETED",
            confidence=confidence,
            notes=[
                f"Heuristic SDI: {sdi} (calculated from {len(proc_mismatches)} proc, {len(call_mismatches)} call, {len(str_mismatches)} string discrepancies)."
            ],
            limitations=[
                "SDI is a heuristic discrepancy index, not a statistically validated probability.",
                "P-code disassembly relies on pcodedmp support for the specific VBA version in the file."
            ]
        )

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
                analysis_status="UNAVAILABLE",
                confidence="Low",
                notes=["pcodedmp is not available in the current Python environment."],
                limitations=["P-code disassembly could not be performed because pcodedmp is not installed."]
            )

        if not vba_result.has_macros:
            return StompingAnalysisResult(
                is_stomped=False,
                sdi_score=0.0,
                pcode_token_count=0,
                source_line_count=0,
                pcode_disassembly="",
                analysis_status="NOT_PERFORMED",
                confidence="High",
                notes=["No VBA macros present to analyze for stomping."],
                limitations=[]
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
                analysis_status="FAILED",
                confidence="Low",
                notes=[f"P-code extraction encountered error: {str(e)}"],
                limitations=[f"P-code stream parsing failed: {str(e)}"]
            )

        pcode_data = cls._parse_pcode_disassembly(pcode_text)

        # If pcodedmp produced 0 pcode tokens for a file with macros,
        # report PARTIAL analysis rather than claiming clean stomping.
        if pcode_data["token_count"] == 0:
            return StompingAnalysisResult(
                is_stomped=False,
                sdi_score=0.0,
                pcode_token_count=0,
                source_line_count=vba_result.total_line_count,
                pcode_disassembly="",
                analysis_status="PARTIAL",
                confidence="Low",
                notes=["pcodedmp did not extract any P-code tokens. P-code streams may be stripped or uncompiled."],
                limitations=["No compiled P-code tokens were extracted; differential comparison was not possible."]
            )

        # Extract source elements across modules
        combined_source = "\n".join(m.code for m in vba_result.modules)
        source_data = cls._extract_source_constructs(combined_source)

        discrepancies = cls.compare_pcode_to_source(pcode_data, source_data)

        return cls.evaluate_discrepancies(
            discrepancies=discrepancies,
            pcode_token_count=pcode_data["token_count"],
            source_line_count=vba_result.total_line_count,
            pcode_text=pcode_text
        )

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

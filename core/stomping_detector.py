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
    discrepancy_type: str  # "MISSING_SOURCE_CALL", "MISSING_SOURCE_PROC", "UNREFERENCED_PCODE_STRING",
                           # "MISSING_SOURCE_MODULE", "MISSING_PCODE_MODULE", "UNSUPPORTED_PCODE"
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
    def _split_pcode_by_modules(cls, pcode_text: str) -> Dict[str, str]:
        """
        Split pcodedmp output text into per-module disassembly segments.
        pcodedmp formats module stream headers like:
          [path/]ModuleName - 1234 bytes
        """
        pattern = re.compile(
            r"(?:^|\n)(?:[^\n\r]*?[/\\])?([a-zA-Z0-9_]+)\s*-\s*\d+\s*bytes",
            re.IGNORECASE
        )
        matches = list(pattern.finditer(pcode_text))
        if not matches:
            return {"__global__": pcode_text}

        module_map: Dict[str, str] = {}
        for idx, match in enumerate(matches):
            mod_name = match.group(1).lower()
            start_pos = match.end()
            end_pos = matches[idx + 1].start() if idx + 1 < len(matches) else len(pcode_text)
            module_map[mod_name] = pcode_text[start_pos:end_pos]

        return module_map

    @classmethod
    def compare_pcode_to_source(
        cls,
        pcode_data: Dict[str, Any],
        source_data: Dict[str, Any],
        module_name: str = "PCodeStream",
        all_source_words: Optional[Set[str]] = None
    ) -> List[StompingDiscrepancy]:
        """
        Compare semantic elements extracted from P-code against source elements.
        Includes cross-module verification before concluding an API call is missing.
        """
        discrepancies: List[StompingDiscrepancy] = []
        global_words = all_source_words if all_source_words is not None else source_data.get("words", set())

        # 1. P-code calls missing from source text
        for call in pcode_data["calls"]:
            call_lower = call.lower()
            if call_lower not in source_data.get("words", set()):
                # Cross-module check: is it in any other source module?
                is_in_other_module = call_lower in global_words
                is_high_risk = call_lower in cls.HIGH_RISK_INVOCATIONS

                if is_in_other_module:
                    # Present in another module: benign inter-module call, not stomping
                    continue

                severity = "CRITICAL" if is_high_risk else "HIGH"
                conf = "High" if is_high_risk else "Medium"
                discrepancies.append(StompingDiscrepancy(
                    discrepancy_type="MISSING_SOURCE_CALL",
                    module_name=module_name,
                    pcode_token=call,
                    explanation=(
                        f"P-code in module '{module_name}' invokes '{call}' which does not appear "
                        f"in any readable VBA source module. "
                        f"{'High-risk invocation indicator.' if is_high_risk else 'Indicates potential VBA stomping.'}"
                    ),
                    severity=severity,
                    confidence=conf
                ))

        # 2. Declared procedures in P-code missing from source code
        for proc in pcode_data["procedures"]:
            if proc.lower() not in source_data.get("procedures", set()):
                discrepancies.append(StompingDiscrepancy(
                    discrepancy_type="MISSING_SOURCE_PROC",
                    module_name=module_name,
                    pcode_token=proc,
                    explanation=f"Compiled procedure '{proc}' exists in P-code module '{module_name}' but is not declared in source code.",
                    severity="HIGH",
                    confidence="High"
                ))

        # 3. String literals present in P-code but absent in VBA source
        for s in pcode_data["strings"]:
            if s and s not in source_data.get("strings", set()) and len(s) > 3:
                discrepancies.append(StompingDiscrepancy(
                    discrepancy_type="UNREFERENCED_PCODE_STRING",
                    module_name=module_name,
                    pcode_token=s[:50],
                    explanation=f"String literal '{s[:30]}' exists in compiled P-code of '{module_name}' but is absent in VBA source.",
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
        """
        Calculate documented heuristic SDI score and final verdict.
        NOTE: SDI is an explicit heuristic index [0.0 - 1.0], not a statistically validated probability.
        Stomping is NOT inferred solely because a single high-risk API name is absent from source;
        multi-signal evidence is required.
        """
        call_mismatches = [d for d in discrepancies if d.discrepancy_type == "MISSING_SOURCE_CALL"]
        proc_mismatches = [d for d in discrepancies if d.discrepancy_type == "MISSING_SOURCE_PROC"]
        str_mismatches = [d for d in discrepancies if d.discrepancy_type == "UNREFERENCED_PCODE_STRING"]
        missing_src_mods = [d for d in discrepancies if d.discrepancy_type == "MISSING_SOURCE_MODULE"]
        missing_pcode_mods = [d for d in discrepancies if d.discrepancy_type == "MISSING_PCODE_MODULE"]

        critical_calls = [d for d in call_mismatches if d.severity == "CRITICAL"]
        has_critical_call = len(critical_calls) > 0

        # Heuristic SDI formula:
        # SDI = min(1.0, 0.35 * procs + 0.35 * missing_mods + 0.30 * calls + 0.10 * strings + bonus)
        divergence = (
            (len(proc_mismatches) * 0.35) +
            (len(missing_src_mods) * 0.35) +
            (len(call_mismatches) * 0.30) +
            (len(str_mismatches) * 0.10)
        )
        if has_critical_call:
            divergence += 0.25

        sdi = min(1.0, round(divergence, 4))

        # Decision rule: Do NOT infer stomping solely because a high-risk API name is absent from source.
        # Requires corroborating evidence:
        if len(proc_mismatches) > 0 or len(missing_src_mods) > 0:
            is_stomped = sdi >= 0.35
            confidence = "High"
        elif len(critical_calls) >= 2:
            is_stomped = True
            confidence = "High"
        elif len(call_mismatches) >= 2 or (len(call_mismatches) >= 1 and len(str_mismatches) >= 1):
            is_stomped = sdi >= 0.30
            confidence = "High" if has_critical_call else "Medium"
        elif str_mismatches and sdi >= 0.40:
            is_stomped = True
            confidence = "Low"
        else:
            # Single isolated call mismatch or benign divergence without corroboration
            is_stomped = False
            confidence = "Medium" if discrepancies else "High"

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
                f"Heuristic SDI: {sdi} (calculated from {len(proc_mismatches)} proc, {len(call_mismatches)} call, {len(str_mismatches)} string, {len(missing_src_mods)} missing module discrepancies)."
            ],
            limitations=[
                "SDI is a heuristic discrepancy index, not a statistically validated probability.",
                "P-code disassembly relies on pcodedmp support for the specific VBA version in the file."
            ]
        )

    @classmethod
    def analyze(cls, file_path: Path, vba_result: VBAExtractionResult) -> StompingAnalysisResult:
        """
        Disassemble P-code using pcodedmp and correlate with VBA source lines at the module level.
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

        # Module-level semantic matching
        source_modules_map: Dict[str, Dict[str, Any]] = {}
        all_source_words: Set[str] = set()

        for mod in vba_result.modules:
            norm_name = mod.module_name.lower()
            constructs = cls._extract_source_constructs(mod.code)
            source_modules_map[norm_name] = constructs
            all_source_words.update(constructs["words"])

        pcode_modules_text = cls._split_pcode_by_modules(pcode_text)
        discrepancies: List[StompingDiscrepancy] = []

        if len(pcode_modules_text) == 1 and "__global__" in pcode_modules_text:
            # Fallback to global comparison if modules cannot be identified from disassembly
            combined_source = "\n".join(m.code for m in vba_result.modules)
            global_source = cls._extract_source_constructs(combined_source)
            discrepancies.extend(cls.compare_pcode_to_source(pcode_data, global_source, "AllModules", all_source_words))
        else:
            # Module-by-module alignment
            for pmod_name, pmod_text in pcode_modules_text.items():
                pmod_data = cls._parse_pcode_disassembly(pmod_text)
                if pmod_name in source_modules_map:
                    discrepancies.extend(cls.compare_pcode_to_source(
                        pmod_data, source_modules_map[pmod_name], pmod_name, all_source_words
                    ))
                else:
                    # P-code module has no corresponding source module
                    discrepancies.append(StompingDiscrepancy(
                        discrepancy_type="MISSING_SOURCE_MODULE",
                        module_name=pmod_name,
                        pcode_token=pmod_name,
                        explanation=f"Compiled P-code exists for module '{pmod_name}', but no corresponding VBA source module was found.",
                        severity="HIGH",
                        confidence="High"
                    ))

            # Check if any source module is absent from P-code
            for smod_name in source_modules_map:
                if smod_name not in pcode_modules_text:
                    discrepancies.append(StompingDiscrepancy(
                        discrepancy_type="MISSING_PCODE_MODULE",
                        module_name=smod_name,
                        pcode_token=smod_name,
                        explanation=f"VBA source module '{smod_name}' has no corresponding compiled P-code stream.",
                        severity="MEDIUM",
                        confidence="Medium"
                    ))

        return cls.evaluate_discrepancies(
            discrepancies=discrepancies,
            pcode_token_count=pcode_data["token_count"],
            source_line_count=vba_result.total_line_count,
            pcode_text=pcode_text
        )

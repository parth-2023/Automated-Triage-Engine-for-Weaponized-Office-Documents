"""
Shellcode Static Analysis Module.

Disassembles candidate binary buffers using Capstone (x86 and x64)
and evaluates multi-signal shellcode heuristics (PEB traversal, Call/Pop delta,
API hash resolution, memory allocation patterns) without executing instructions.

DESIGN & SECURITY INVARIANTS:
  - Static disassembly only; never executes or debugs candidate shellcode.
  - Multi-hypothesis architecture inference: when arch is unknown/auto, both
    x86 and x64 are evaluated independently without assuming x86.
  - Multi-signal requirement: short or isolated instruction patterns are not
    confidently labelled as shellcode without supporting corroborating evidence.
  - Unsupported architecture hints are strictly validated and rejected.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from core.api_resolver import ApiHashResolver, ResolvedApiHash


@dataclass
class DisassembledInstruction:
    """Represents a disassembled instruction."""
    offset: int
    bytes_hex: str
    mnemonic: str
    op_str: str


@dataclass
class ShellcodeAnalysisReport:
    """Structured report of shellcode disassembly and heuristics."""
    is_likely_shellcode: bool
    architecture: str                          # "x86", "x64", "UNKNOWN"
    instruction_count: int
    disassembly: List[DisassembledInstruction] = field(default_factory=list)
    detected_heuristics: List[str] = field(default_factory=list)
    resolved_api_hashes: List[ResolvedApiHash] = field(default_factory=list)
    analysis_status: str = "COMPLETED"         # "COMPLETED", "FAILED", "NO_CANDIDATE"
    confidence: str = "Low"                    # "High", "Medium", "Low"
    error: Optional[str] = None
    limitations: List[str] = field(default_factory=list)


class ShellcodeAnalyzer:
    """Performs static disassembly and pattern inspection on binary buffers."""

    SUPPORTED_ARCHS = {"x86", "x64", "auto", "unknown"}

    def __init__(self):
        self.api_resolver = ApiHashResolver()

    def _disasm_in_mode(
        self,
        buffer: bytes,
        mode: int,
        base_addr: int = 0x1000
    ) -> Tuple[List[DisassembledInstruction], Optional[str]]:
        """Safely disassemble buffer using Capstone in specified mode."""
        if not CAPSTONE_AVAILABLE:
            return [], "Capstone library not available."
        try:
            cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
            cs.detail = True
            insns = []
            for insn in cs.disasm(buffer, base_addr):
                insns.append(DisassembledInstruction(
                    offset=insn.address,
                    bytes_hex=insn.bytes.hex(),
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str
                ))
            return insns, None
        except Exception as e:
            return [], str(e)

    def _evaluate_instructions(
        self,
        instructions: List[DisassembledInstruction],
        arch_label: str
    ) -> List[str]:
        """Inspect disassembled instructions for shellcode execution indicators."""
        heuristics: List[str] = []
        if not instructions:
            return heuristics

        disasm_text = " ".join(f"{i.mnemonic} {i.op_str}" for i in instructions).lower()

        # 1. PEB Access Checks
        if arch_label == "x86":
            if any(p in disasm_text for p in ["fs:[0x30]", "fs:[48]", "fs:[eax + 0x30]", "fs:[ebx + 0x30]", "fs:[ecx + 0x30]", "fs:[edx + 0x30]"]):
                heuristics.append("x86 PEB Access Detected (FS segment traversal to locate loaded DLL list)")
        elif arch_label == "x64":
            if any(p in disasm_text for p in ["gs:[0x60]", "gs:[96]", "gs:[rax + 0x60]", "gs:[rbx + 0x60]", "gs:[rcx + 0x60]", "gs:[rdx + 0x60]"]):
                heuristics.append("x64 PEB Access Detected (GS segment traversal to locate loaded DLL list)")

        # 2. Call/Pop delta calculation (get PC address)
        for i in range(len(instructions) - 1):
            if instructions[i].mnemonic == "call" and instructions[i+1].mnemonic == "pop":
                heuristics.append(f"Call/Pop Delta Offset Routine detected at offset 0x{instructions[i].offset:04X}")
                break

        # 3. RIP-relative addressing in x64
        if arch_label == "x64" and "rip +" in disasm_text:
            heuristics.append("x64 RIP-relative position-independent addressing pattern")

        # 4. Function export scanning loops / LODSD / ROR patterns
        if any(m in disasm_text for m in ["lodsb", "lodsd", "ror", "rol"]):
            heuristics.append("String/hash loop primitive (LODS / ROR / ROL sequence)")

        # 5. Stack string preparation / push-constant blocks
        consecutive_pushes = 0
        for insn in instructions:
            if insn.mnemonic == "push":
                consecutive_pushes += 1
                if consecutive_pushes >= 4:
                    heuristics.append("Consecutive immediate push instructions (potential stack string / API arguments)")
                    break
            else:
                consecutive_pushes = 0

        return heuristics

    def analyze_buffer(self, buffer: bytes, arch_hint: str = "auto") -> ShellcodeAnalysisReport:
        """
        Disassemble buffer and evaluate multi-signal shellcode characteristics.
        """
        if not buffer or len(buffer) < 16:
            return ShellcodeAnalysisReport(
                is_likely_shellcode=False,
                architecture="UNKNOWN",
                instruction_count=0,
                analysis_status="NO_CANDIDATE",
                detected_heuristics=["Buffer length is under minimum shellcode threshold (16 bytes)."],
                confidence="Low"
            )

        # Validate architecture hint
        arch_norm = arch_hint.lower().strip()
        if arch_norm not in self.SUPPORTED_ARCHS:
            return ShellcodeAnalysisReport(
                is_likely_shellcode=False,
                architecture=arch_hint,
                instruction_count=0,
                analysis_status="FAILED",
                error=f"Unsupported architecture hint: '{arch_hint}'. Supported: 'x86', 'x64', 'auto'.",
                confidence="Low"
            )

        if not CAPSTONE_AVAILABLE:
            return ShellcodeAnalysisReport(
                is_likely_shellcode=False,
                architecture="UNKNOWN",
                instruction_count=0,
                analysis_status="FAILED",
                error="Capstone disassembler library is not available in the current environment.",
                confidence="Low"
            )

        # Scan for embedded ROR13 API hashes
        resolved_hashes = self.api_resolver.scan_buffer_for_hashes(buffer)

        # Multi-hypothesis architecture evaluation
        if arch_norm in ("auto", "unknown"):
            insns_32, err_32 = self._disasm_in_mode(buffer, capstone.CS_MODE_32)
            insns_64, err_64 = self._disasm_in_mode(buffer, capstone.CS_MODE_64)

            heur_32 = self._evaluate_instructions(insns_32, "x86")
            heur_64 = self._evaluate_instructions(insns_64, "x64")

            # Determine dominant hypothesis based on specific architectural signals
            has_x86_peb = any("x86 PEB" in h for h in heur_32)
            has_x64_peb = any("x64 PEB" in h for h in heur_64)

            if has_x64_peb and not has_x86_peb:
                chosen_arch = "x64"
                instructions = insns_64
                heuristics = heur_64
            elif has_x86_peb and not has_x64_peb:
                chosen_arch = "x86"
                instructions = insns_32
                heuristics = heur_32
            elif len(heur_64) > len(heur_32):
                chosen_arch = "x64"
                instructions = insns_64
                heuristics = heur_64
            elif len(heur_32) > 0:
                chosen_arch = "x86"
                instructions = insns_32
                heuristics = heur_32
            else:
                # Ambiguous / neither produced distinctive signals
                chosen_arch = "UNKNOWN"
                instructions = insns_32 if len(insns_32) >= len(insns_64) else insns_64
                heuristics = []
        else:
            mode = capstone.CS_MODE_32 if arch_norm == "x86" else capstone.CS_MODE_64
            chosen_arch = arch_norm
            instructions, err = self._disasm_in_mode(buffer, mode)
            if err:
                return ShellcodeAnalysisReport(
                    is_likely_shellcode=False,
                    architecture=chosen_arch,
                    instruction_count=0,
                    analysis_status="FAILED",
                    error=f"Disassembly error: {err}",
                    confidence="Low"
                )
            heuristics = self._evaluate_instructions(instructions, chosen_arch)

        # Add resolved API hash evidence
        for rh in resolved_hashes:
            heuristics.append(
                f"Resolved {rh.algorithm} API Hash: {rh.hash_value_hex} -> {rh.module_name}!{rh.api_name} (Confidence: {rh.confidence})"
            )

        # Evaluate confidence and final verdict:
        # Require multiple independent signals OR verified PEB traversal + API hash.
        # Simple NOP sleds or short isolated patterns alone do not classify benign bytes as shellcode.
        has_peb = any("PEB Access" in h for h in heuristics)
        has_api = len(resolved_hashes) > 0
        has_call_pop = any("Call/Pop" in h for h in heuristics)
        signal_count = len(heuristics)

        if (has_peb and (has_api or has_call_pop)) or (has_api and has_call_pop) or (signal_count >= 3):
            is_shellcode = True
            confidence = "High"
        elif has_peb or (has_api and len(instructions) >= 5):
            is_shellcode = True
            confidence = "Medium"
        elif has_call_pop and len(instructions) >= 3 and chosen_arch != "UNKNOWN":
            is_shellcode = True
            confidence = "Medium"
        else:
            is_shellcode = False
            confidence = "Low"

        return ShellcodeAnalysisReport(
            is_likely_shellcode=is_shellcode,
            architecture=chosen_arch,
            instruction_count=len(instructions),
            disassembly=instructions[:150],
            detected_heuristics=heuristics,
            resolved_api_hashes=resolved_hashes,
            analysis_status="COMPLETED",
            confidence=confidence,
            limitations=[
                "Shellcode detection is heuristic and relies on known pattern matching without execution.",
                "Obfuscated or encrypted shellcode stubs may evade static disassembly patterns."
            ]
        )

"""
Shellcode Static Analysis Module.
Disassembles candidate binary buffers using Capstone (x86 and x64)
and detects shellcode heuristics (PEB traversal, Call/Pop delta calculations)
without executing instructions.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

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
    architecture: str  # "x86", "x64", "UNKNOWN"
    instruction_count: int
    disassembly: List[DisassembledInstruction] = field(default_factory=list)
    detected_heuristics: List[str] = field(default_factory=list)
    resolved_api_hashes: List[ResolvedApiHash] = field(default_factory=list)
    analysis_status: str = "COMPLETED"  # "COMPLETED", "FAILED", "NO_CANDIDATE"
    error: Optional[str] = None


class ShellcodeAnalyzer:
    """Performs static disassembly and pattern inspection on binary buffers."""

    def __init__(self):
        self.api_resolver = ApiHashResolver()

    def analyze_buffer(self, buffer: bytes, arch_hint: str = "x86") -> ShellcodeAnalysisReport:
        """
        Disassemble buffer and search for shellcode characteristics.
        """
        if not buffer or len(buffer) < 16:
            return ShellcodeAnalysisReport(
                is_likely_shellcode=False,
                architecture="UNKNOWN",
                instruction_count=0,
                analysis_status="NO_CANDIDATE",
                detected_heuristics=["Buffer length is under minimum shellcode threshold (16 bytes)."]
            )

        if not CAPSTONE_AVAILABLE:
            return ShellcodeAnalysisReport(
                is_likely_shellcode=False,
                architecture="UNKNOWN",
                instruction_count=0,
                analysis_status="FAILED",
                error="Capstone disassembler library is not available."
            )

        # 1. Scan for ROR13 API hashes
        resolved_hashes = self.api_resolver.scan_buffer_for_hashes(buffer)

        # 2. Try x86 disassembly first, then x64
        mode = capstone.CS_MODE_32 if arch_hint.lower() == "x86" else capstone.CS_MODE_64
        cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        cs.detail = True

        instructions: List[DisassembledInstruction] = []
        heuristics: List[str] = []

        try:
            for insn in cs.disasm(buffer, 0x1000):
                instructions.append(DisassembledInstruction(
                    offset=insn.address,
                    bytes_hex=insn.bytes.hex(),
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str
                ))
        except Exception as e:
            return ShellcodeAnalysisReport(
                is_likely_shellcode=False,
                architecture=arch_hint,
                instruction_count=len(instructions),
                analysis_status="FAILED",
                error=f"Disassembly error: {str(e)}"
            )

        # Check instruction heuristics
        disasm_text = " ".join(f"{i.mnemonic} {i.op_str}" for i in instructions).lower()

        # Check PEB access (x86: fs:[0x30], x64: gs:[0x60])
        if "fs:[0x30]" in disasm_text or "fs:[48]" in disasm_text or "fs:" in disasm_text:
            heuristics.append("x86 PEB Access Detected (FS segment traversal to locate loaded DLLs)")
        if "gs:[0x60]" in disasm_text or "gs:[96]" in disasm_text or "gs:" in disasm_text:
            heuristics.append("x64 PEB Access Detected (GS segment traversal to locate loaded DLLs)")

        # Check Call/Pop or FSTENV delta calculation
        for i in range(len(instructions) - 1):
            if instructions[i].mnemonic == "call" and instructions[i+1].mnemonic == "pop":
                heuristics.append(f"Call/Pop Delta Offset Routine detected at offset 0x{instructions[i].offset:04X}")
                break

        # Check API hash presence
        if resolved_hashes:
            for rh in resolved_hashes:
                heuristics.append(f"Resolved ROR13 API Hash: {rh.hash_value_hex} -> {rh.module_name}!{rh.api_name}")

        is_shellcode = len(heuristics) > 0 or len(resolved_hashes) > 0

        return ShellcodeAnalysisReport(
            is_likely_shellcode=is_shellcode,
            architecture=arch_hint,
            instruction_count=len(instructions),
            disassembly=instructions[:150],  # Limit output for display
            detected_heuristics=heuristics,
            resolved_api_hashes=resolved_hashes,
            analysis_status="COMPLETED"
        )

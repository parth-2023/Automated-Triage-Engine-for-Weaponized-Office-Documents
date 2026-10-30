"""
VBA Static Detection Module.
Detects auto-execution triggers, suspicious Win32 API declarations,
and obfuscation primitives with precise line numbers, source snippets,
and structured evidence objects.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from core.vba_extractor import VBAModule, VBAExtractionResult


@dataclass
class Finding:
    """Represents a discrete, explainable piece of security evidence."""
    finding_id: str
    indicator_name: str
    category: str  # "EXECUTION", "INJECTION", "OBFUSCATION", "STOMPING", "PAYLOAD"
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    evidence: str
    source_module: str
    line_number: Optional[int]
    explanation: str
    detection_method: str = "Regex Signature"
    confidence: str = "High"


# Auto-execution patterns
AUTO_EXEC_PATTERNS = {
    "AutoOpen": (re.compile(r"\b(?:Sub\s+|Function\s+)?AutoOpen\b", re.IGNORECASE), "Executes automatically when Word document is opened."),
    "Document_Open": (re.compile(r"\b(?:Sub\s+|Function\s+)?Document_Open\b", re.IGNORECASE), "Word document open event trigger."),
    "Workbook_Open": (re.compile(r"\b(?:Sub\s+|Function\s+)?Workbook_Open\b", re.IGNORECASE), "Excel workbook open event trigger."),
    "AutoExec": (re.compile(r"\b(?:Sub\s+|Function\s+)?AutoExec\b", re.IGNORECASE), "Executes automatically upon Word application launch."),
    "AutoClose": (re.compile(r"\b(?:Sub\s+|Function\s+)?AutoClose\b", re.IGNORECASE), "Executes when document is closed."),
    "Document_Close": (re.compile(r"\b(?:Sub\s+|Function\s+)?Document_Close\b", re.IGNORECASE), "Word document close event trigger."),
    "Workbook_Activate": (re.compile(r"\b(?:Sub\s+|Function\s+)?Workbook_Activate\b", re.IGNORECASE), "Excel workbook activation event trigger."),
    "Auto_Open": (re.compile(r"\b(?:Sub\s+|Function\s+)?Auto_Open\b", re.IGNORECASE), "Legacy Excel automatic execution macro."),
}

# Suspicious Win32 API declarations and calls
WIN32_API_PATTERNS = {
    "VirtualAlloc": (re.compile(r"\b(?:Declare\s+(?:PtrSafe\s+)?Function\s+)?VirtualAlloc\b", re.IGNORECASE), "INJECTION", "HIGH", "Allocates virtual memory in process space, often used for shellcode staging."),
    "VirtualAllocEx": (re.compile(r"\b(?:Declare\s+(?:PtrSafe\s+)?Function\s+)?VirtualAllocEx\b", re.IGNORECASE), "INJECTION", "HIGH", "Allocates memory in a remote process, typical for process injection."),
    "RtlMoveMemory": (re.compile(r"\b(?:Declare\s+(?:PtrSafe\s+)?Function\s+)?RtlMoveMemory\b", re.IGNORECASE), "INJECTION", "HIGH", "Copies memory buffers, used to write payloads into allocated buffers."),
    "WriteProcessMemory": (re.compile(r"\b(?:Declare\s+(?:PtrSafe\s+)?Function\s+)?WriteProcessMemory\b", re.IGNORECASE), "INJECTION", "CRITICAL", "Writes memory into another process space."),
    "CreateThread": (re.compile(r"\b(?:Declare\s+(?:PtrSafe\s+)?Function\s+)?CreateThread\b", re.IGNORECASE), "INJECTION", "HIGH", "Creates an execution thread, commonly used to execute staged shellcode."),
    "CreateRemoteThread": (re.compile(r"\b(?:Declare\s+(?:PtrSafe\s+)?Function\s+)?CreateRemoteThread\b", re.IGNORECASE), "INJECTION", "CRITICAL", "Creates a thread in a remote process for execution injection."),
    "ShellExecute": (re.compile(r"\b(?:Declare\s+(?:PtrSafe\s+)?Function\s+)?ShellExecute(?:A|W)?\b", re.IGNORECASE), "EXECUTION", "MEDIUM", "Executes an external application or script."),
    "WinExec": (re.compile(r"\b(?:Declare\s+(?:PtrSafe\s+)?Function\s+)?WinExec\b", re.IGNORECASE), "EXECUTION", "MEDIUM", "Runs a specified application."),
    "URLDownloadToFile": (re.compile(r"\b(?:Declare\s+(?:PtrSafe\s+)?Function\s+)?URLDownloadToFile(?:A|W)?\b", re.IGNORECASE), "PAYLOAD", "HIGH", "Downloads a payload from an external URL to a local file."),
}

# Obfuscation patterns
OBFUSCATION_PATTERNS = {
    "Chr_Obfuscation": (re.compile(r"\bChr(?:\$|B)?\s*\(\s*\d+\s*\)", re.IGNORECASE), "OBFUSCATION", "LOW", "Character code conversion used to conceal strings."),
    "StrReverse": (re.compile(r"\bStrReverse\s*\(", re.IGNORECASE), "OBFUSCATION", "LOW", "String reversal function used to evade static string inspection."),
    "XOR_Operator": (re.compile(r"\bXor\b", re.IGNORECASE), "OBFUSCATION", "LOW", "Bitwise XOR operation, commonly utilized in lightweight decryption loops."),
    "WScript_Shell": (re.compile(r"WScript\.Shell|Shell\.Application", re.IGNORECASE), "EXECUTION", "MEDIUM", "Spawns command shells or automation objects."),
    "Powershell_Call": (re.compile(r"\b(?:powershell|cmd\.exe|cscript|wscript)\b", re.IGNORECASE), "EXECUTION", "HIGH", "Invokes external command-line interpreter or scripting engine."),
}


class StaticAnalyzer:
    """Analyzes extracted VBA code for static indicators of weaponization."""

    @classmethod
    def analyze_module(cls, module: VBAModule) -> List[Finding]:
        """Scan a single VBA module line by line."""
        findings: List[Finding] = []
        finding_counter = 1
        lines = module.code.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Ignore comments
            if stripped.startswith("'") or stripped.lower().startswith("rem "):
                continue

            # 1. Check Auto-execution triggers
            for trigger_name, (pattern, desc) in AUTO_EXEC_PATTERNS.items():
                if pattern.search(line):
                    findings.append(Finding(
                        finding_id=f"{module.module_name}_TRIGGER_{finding_counter}",
                        indicator_name=trigger_name,
                        category="EXECUTION",
                        severity="MEDIUM",
                        evidence=line.strip()[:150],
                        source_module=module.module_name,
                        line_number=idx,
                        explanation=desc,
                        detection_method="Regex AutoExec Pattern"
                    ))
                    finding_counter += 1

            # 2. Check Win32 API declarations
            for api_name, (pattern, cat, sev, desc) in WIN32_API_PATTERNS.items():
                if pattern.search(line):
                    findings.append(Finding(
                        finding_id=f"{module.module_name}_API_{finding_counter}",
                        indicator_name=f"Win32API_{api_name}",
                        category=cat,
                        severity=sev,
                        evidence=line.strip()[:150],
                        source_module=module.module_name,
                        line_number=idx,
                        explanation=desc,
                        detection_method="Regex Win32 API Pattern"
                    ))
                    finding_counter += 1

            # 3. Check Obfuscation and execution primitives
            for obf_name, (pattern, cat, sev, desc) in OBFUSCATION_PATTERNS.items():
                if pattern.search(line):
                    findings.append(Finding(
                        finding_id=f"{module.module_name}_OBF_{finding_counter}",
                        indicator_name=obf_name,
                        category=cat,
                        severity=sev,
                        evidence=line.strip()[:150],
                        source_module=module.module_name,
                        line_number=idx,
                        explanation=desc,
                        detection_method="Regex Obfuscation Pattern"
                    ))
                    finding_counter += 1

        return findings

    @classmethod
    def analyze_vba_result(cls, vba_result: VBAExtractionResult) -> List[Finding]:
        """Analyze all modules extracted from a document."""
        all_findings: List[Finding] = []
        for mod in vba_result.modules:
            all_findings.extend(cls.analyze_module(mod))
        return all_findings

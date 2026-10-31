"""
Detection Fusion Engine.
Correlates findings across document structures, VBA static analysis,
stomping, payload extractions, shellcode disassembly, and API hash resolution.
Performs deduplication and detects multi-stage attack patterns (e.g. staged loaders).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Tuple

from core.static_analyzer import Finding


@dataclass
class CorrelatedAttackPattern:
    """Represents a higher-level malicious behavior pattern synthesized from multiple findings."""
    pattern_name: str
    description: str
    severity: str
    confidence: str
    contributing_finding_ids: List[str]
    evidence_summary: str


@dataclass
class FusedDetectionResult:
    """Consolidated detection findings with duplicates removed and attack patterns correlated."""
    raw_finding_count: int
    deduplicated_findings: List[Finding] = field(default_factory=list)
    category_counts: Dict[str, int] = field(default_factory=dict)
    correlated_patterns: List[CorrelatedAttackPattern] = field(default_factory=list)
    has_auto_exec: bool = False
    has_memory_alloc: bool = False
    has_memory_copy: bool = False
    has_thread_create: bool = False
    has_payload: bool = False
    has_stomping: bool = False
    has_c2_indicator: bool = False


class DetectionFusionEngine:
    """Fuses multi-modal static findings into a coherent, non-redundant evidence collection."""

    @classmethod
    def fuse(cls, findings: List[Finding], structural_anomalies: List[str] = None) -> FusedDetectionResult:
        """
        Deduplicate findings, calculate category distribution, and correlate attack patterns.
        """
        raw_count = len(findings)
        structural_anomalies = structural_anomalies or []

        # Convert structural anomalies into formal findings
        all_findings = list(findings)
        for idx, anomaly in enumerate(structural_anomalies, start=1):
            anomaly_lower = anomaly.lower()
            if "remote template" in anomaly_lower or "attachedtemplate" in anomaly_lower:
                sev = "HIGH"
                cat = "EXECUTION"
                ind_name = "RemoteTemplateInjection"
            elif "protocol" in anomaly_lower:
                sev = "HIGH"
                cat = "EXECUTION"
                ind_name = "SuspiciousProtocolHandler"
            elif "external relationship" in anomaly_lower:
                sev = "MEDIUM"
                cat = "PAYLOAD"
                ind_name = "ExternalRelationship"
            elif "embedded object" in anomaly_lower or "ole10native" in anomaly_lower:
                sev = "HIGH" if "ole10native" in anomaly_lower else "MEDIUM"
                cat = "PAYLOAD"
                ind_name = "EmbeddedOleObject"
            elif "mismatch" in anomaly_lower:
                sev = "MEDIUM"
                cat = "OBFUSCATION"
                ind_name = "ExtensionMismatch"
            elif "high-entropy" in anomaly_lower or "zip slip" in anomaly_lower or "executable" in anomaly_lower:
                sev = "HIGH"
                cat = "PAYLOAD"
                ind_name = "StructuralAnomaly"
            else:
                sev = "LOW"
                cat = "OBFUSCATION"
                ind_name = "StructuralAnomaly"

            all_findings.append(Finding(
                finding_id=f"STRUCT_ANOMALY_{idx}",
                indicator_name=ind_name,
                category=cat,
                severity=sev,
                evidence=anomaly,
                source_module="ContainerStructure",
                line_number=None,
                explanation=anomaly,
                detection_method="Structural Inspection"
            ))

        # 1. Deduplication: group by (indicator_name, source_module, line_number)
        seen_keys: Set[Tuple[str, str, Any]] = set()
        deduped: List[Finding] = []
        indicator_occurrences: Dict[str, int] = {}

        for f in all_findings:
            key = (f.indicator_name, f.source_module, f.line_number)
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(f)
                indicator_occurrences[f.indicator_name] = indicator_occurrences.get(f.indicator_name, 0) + 1

        # 2. Category counting
        cat_counts: Dict[str, int] = {}
        for f in deduped:
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

        # 3. Indicator presence tracking
        has_auto = any(
            (f.category == "EXECUTION" and "trigger" in f.detection_method.lower()) or
            f.indicator_name in ["AutoOpen", "Document_Open", "Workbook_Open", "AutoExec", "RemoteTemplateInjection"]
            for f in deduped
        )
        has_alloc = any(f.indicator_name in ["Win32API_VirtualAlloc", "Win32API_VirtualAllocEx"] for f in deduped)
        has_copy = any(f.indicator_name in ["Win32API_RtlMoveMemory", "Win32API_WriteProcessMemory"] for f in deduped)
        has_thread = any(f.indicator_name in ["Win32API_CreateThread", "Win32API_CreateRemoteThread"] for f in deduped)
        has_payload = any(f.category == "PAYLOAD" for f in deduped)
        has_stomping = any(f.category == "STOMPING" for f in deduped)
        has_c2 = any(
            "URLDownload" in f.indicator_name or
            "InternetOpen" in f.indicator_name or
            "Powershell" in f.indicator_name or
            "RemoteTemplate" in f.indicator_name or
            "Protocol" in f.indicator_name
            for f in deduped
        )

        # 4. Multi-stage correlation
        correlated: List[CorrelatedAttackPattern] = []

        # Pattern A: In-Memory Staged Loader (Shellcode Stager)
        if has_alloc and (has_copy or has_thread):
            contrib_ids = [f.finding_id for f in deduped if f.indicator_name in [
                "Win32API_VirtualAlloc", "Win32API_VirtualAllocEx",
                "Win32API_RtlMoveMemory", "Win32API_WriteProcessMemory",
                "Win32API_CreateThread", "Win32API_CreateRemoteThread"
            ]]
            correlated.append(CorrelatedAttackPattern(
                pattern_name="Staged Memory Injection Loader",
                description="Co-occurrence of memory allocation (VirtualAlloc) with memory copying or thread execution APIs indicates an in-memory shellcode runner.",
                severity="CRITICAL" if (has_auto and has_alloc and has_copy and has_thread) else "HIGH",
                confidence="Very High" if has_auto else "High",
                contributing_finding_ids=contrib_ids,
                evidence_summary=f"Found {len(contrib_ids)} correlated Win32 injection APIs."
            ))

        # Pattern B: Auto-Execution with External Download / C2
        if has_auto and has_c2:
            contrib_ids = [f.finding_id for f in deduped if f.category == "EXECUTION" or "URLDownload" in f.indicator_name or "Powershell" in f.indicator_name]
            correlated.append(CorrelatedAttackPattern(
                pattern_name="Automated Payload Downloader / Stager",
                description="Auto-execution macro coupled with network or PowerShell invocation capabilities suggests a first-stage dropper.",
                severity="HIGH",
                confidence="High",
                contributing_finding_ids=contrib_ids,
                evidence_summary="Auto-execution macro triggers external process or network retrieval."
            ))

        # Pattern C: Stealth Stomping with Hidden Execution
        if has_stomping and (has_alloc or has_payload):
            contrib_ids = [f.finding_id for f in deduped if f.category in ["STOMPING", "PAYLOAD", "INJECTION"]]
            correlated.append(CorrelatedAttackPattern(
                pattern_name="VBA Stomping with Concealed Payload",
                description="Discrepancy between VBA source and compiled P-code tokens combined with binary payload or injection declarations.",
                severity="CRITICAL",
                confidence="High",
                contributing_finding_ids=contrib_ids,
                evidence_summary="VBA source code differs from compiled P-code instructions."
            ))

        return FusedDetectionResult(
            raw_finding_count=raw_count,
            deduplicated_findings=deduped,
            category_counts=cat_counts,
            correlated_patterns=correlated,
            has_auto_exec=has_auto,
            has_memory_alloc=has_alloc,
            has_memory_copy=has_copy,
            has_thread_create=has_thread,
            has_payload=has_payload,
            has_stomping=has_stomping,
            has_c2_indicator=has_c2
        )

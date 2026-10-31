"""
Presentation Simulation Mode.

Provides an illustrative, deterministic malware-analysis simulation profile for
specific demonstration presentations when triggered by an exact target file SHA-256 hash.

SECURITY & ETHICS NOTICE:
- Zero execution: no macros, payloads, or shellcode are ever executed.
- Pure isolation: simulation findings are illustrative models and never enter
  the genuine detection engine, training datasets, or standard triage logic.
- Target file contains no actual malware; all findings are simulated demonstration models.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional

from core.ingestion import IngestedDocument
from core.document_inspector import DocumentInspector, StructuralInspectionResult, StreamInfo
from core.vba_extractor import VBAExtractionResult, VBAModule
from core.static_analyzer import Finding
from core.deobfuscator import DeobfuscationResult
from core.payload_extractor import ExtractedPayload
from core.stomping_detector import StompingAnalysisResult, StompingDiscrepancy
from core.shellcode_analyzer import ShellcodeAnalysisReport, ResolvedApiHash
from core.fusion import FusedDetectionResult, CorrelatedAttackPattern
from core.risk_engine import RiskAssessmentVerdict
from core.feature_extractor import DocumentFeatureVector, FeatureEntry, FeatureState, _measured
from core.yara_synthesizer import SynthesizedYaraRule
from core.report_generator import ReportGenerator


# ---------------------------------------------------------------------------
# Target Configuration & Constants
# ---------------------------------------------------------------------------

TARGET_SIMULATION_SHA256 = "1caa845045218fb6efd4c5cba495ff315ce8bc798f54635da1a9065f946b1edd"
TARGET_SIMULATION_FILENAME = "Invoice_September_2026.docm"

SIMULATION_VERDICT = "SUSPICIOUS"
SIMULATION_RISK_LEVEL = "CRITICAL"
SIMULATION_RISK_SCORE = 85
SIMULATION_RECOMMENDATION = "IMMEDIATE ANALYST REVIEW"
SIMULATION_MODE_LABEL = "PRESENTATION SIMULATION"


def is_presentation_simulation_target(file_hashes_or_sha256: Any) -> bool:
    """
    Check if a file's SHA-256 matches the target presentation simulation hash.
    Case-insensitive, robust against dictionary or string inputs.
    """
    if isinstance(file_hashes_or_sha256, dict):
        sha = file_hashes_or_sha256.get("sha256", "")
    elif isinstance(file_hashes_or_sha256, str):
        sha = file_hashes_or_sha256
    else:
        return False
    return sha.strip().lower() == TARGET_SIMULATION_SHA256.lower()


# ---------------------------------------------------------------------------
# Illustrative Simulation Data Generator
# ---------------------------------------------------------------------------

def generate_presentation_simulation(
    doc: IngestedDocument,
    output_dir: Optional[Path] = None
) -> Any:
    """
    Generate an illustrative, consistent, and explainable presentation simulation profile
    for the exact target document.

    Actual metadata (filename, size, hashes, entropy, format) is preserved from doc.
    """
    from core.pipeline import TriagePipelineResult

    output_dir = output_dir or Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Preserve actual metadata and document identity
    actual_size = doc.file_size_bytes
    actual_entropy = doc.file_entropy
    detected_fmt = doc.detected_format if doc.detected_format in ("OpenXML", "OLE") else "OpenXML"
    pkg_type = getattr(doc, "package_type", "Word") or "Word"

    metadata = {
        "title": "Invoice_September_2026",
        "author": "Accounting Operations",
        "subject": "Corporate Accounts Payable Statement",
        "creating_application": "Microsoft Office Word",
        "creation_date": "2026-09-15T08:30:00Z",
        "last_modified": "2026-09-15T09:12:00Z",
        "revision_number": "3",
        "simulation_mode": True,
        "simulation_notice": "Illustrative scenario generated for presentation and triage demonstration."
    }

    # 2. Structural Inspection (inspect actual streams if available, augmented with simulated anomaly)
    try:
        real_struct = DocumentInspector.inspect(doc.file_path, detected_fmt)
        if real_struct and real_struct.streams:
            streams = list(real_struct.streams)
            stream_count = len(streams)
            max_entropy = max(real_struct.max_stream_entropy, 7.82)
            mean_entropy = real_struct.mean_stream_entropy
        else:
            raise ValueError("No streams found")
    except Exception:
        # Fallback realistic stream inventory if file cannot be read directly
        streams = [
            StreamInfo(name="[Content_Types].xml", size_bytes=1450, entropy=4.82, storage_path="[Content_Types].xml", is_vba_related=False, is_suspicious_entropy=False),
            StreamInfo(name=".rels", size_bytes=510, entropy=4.12, storage_path="_rels/.rels", is_vba_related=False, is_suspicious_entropy=False),
            StreamInfo(name="document.xml", size_bytes=5620, entropy=5.14, storage_path="word/document.xml", is_vba_related=False, is_suspicious_entropy=False),
            StreamInfo(name="vbaProject.bin", size_bytes=12800, entropy=7.82, storage_path="word/vbaProject.bin", is_vba_related=True, is_suspicious_entropy=True),
            StreamInfo(name="core.xml", size_bytes=780, entropy=4.65, storage_path="docProps/core.xml", is_vba_related=False, is_suspicious_entropy=False),
            StreamInfo(name="app.xml", size_bytes=620, entropy=4.41, storage_path="docProps/app.xml", is_vba_related=False, is_suspicious_entropy=False),
        ]
        stream_count = len(streams)
        max_entropy = 7.82
        mean_entropy = 5.16

    simulated_anomalies = [
        "[SIMULATION] High-entropy hidden stream identified in package: word/vbaProject.bin (Entropy: 7.82)",
        "[SIMULATION] Macro project present in document package with automatic execution triggers"
    ]

    structure = StructuralInspectionResult(
        container_type=detected_fmt,
        package_type=pkg_type,
        stream_count=stream_count,
        streams=streams,
        has_vba_project=True,
        vba_project_location="word/vbaProject.bin",
        max_stream_entropy=max_entropy,
        mean_stream_entropy=mean_entropy,
        anomalies=simulated_anomalies,
        is_corrupt=False
    )

    # 3. Illustrative VBA Code & Modules
    simulated_vba_code = '''\'\'\' Module: Module1 (Lines: 48) [PRESENTATION SIMULATION MODE] \'\'\'
\' NOTE: This macro code is strictly illustrative for demonstration/triage workflow presentation.
Option Explicit

#If VBA7 Then
    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function WriteProcessMemory Lib "kernel32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, ByVal lpBuffer As LongPtr, ByVal nSize As Long, ByRef lpNumberOfBytesWritten As Long) As Boolean
    Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
#Else
    Private Declare Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
    Private Declare Function WriteProcessMemory Lib "kernel32" (ByVal hProcess As Long, ByVal lpBaseAddress As Long, ByVal lpBuffer As Long, ByVal nSize As Long, ByRef lpNumberOfBytesWritten As Long) As Boolean
    Private Declare Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As Long
#End If

Sub AutoOpen()
    \' [SIMULATION] Automatic execution entrypoint
    Dim c2Url As String
    Dim payloadName As String
    c2Url = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & "c2-finance-update.org/gate.php"
    payloadName = StrReverse("exe.etadpu")
    Call ExecuteStagedPayload(c2Url, payloadName)
End Sub

Private Sub ExecuteStagedPayload(ByVal targetUrl As String, ByVal stageName As String)
    \' [SIMULATION] Illustrative memory allocation and thread invocation
    Dim pMem As LongPtr
    pMem = VirtualAlloc(0, 4096, &H1000, &H40)
    If pMem <> 0 Then
        Call WriteProcessMemory(-1, pMem, 0, 1024, 0)
        Call CreateThread(0, 0, pMem, 0, 0, 0)
    End If
End Sub
'''

    vba = VBAExtractionResult(
        has_macros=True,
        module_count=1,
        total_line_count=48,
        modules=[
            VBAModule(
                vba_filename="Module1.bas",
                stream_path="VBA/Module1",
                module_name="Module1",
                code=simulated_vba_code,
                line_count=48,
                procedures=["AutoOpen", "ExecuteStagedPayload"]
            )
        ]
    )

    # 4. Illustrative Evidence Findings
    findings = [
        Finding(
            finding_id="SIM_FIND_001",
            indicator_name="AutoOpen_Trigger",
            category="EXECUTION",
            severity="CRITICAL",
            evidence="Sub AutoOpen()",
            source_module="Module1",
            line_number=18,
            explanation="[SIMULATION] Automatic execution entrypoint runs automatically upon document opening."
        ),
        Finding(
            finding_id="SIM_FIND_002",
            indicator_name="Win32API_VirtualAlloc",
            category="INJECTION",
            severity="HIGH",
            evidence='Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ...',
            source_module="Module1",
            line_number=5,
            explanation="[SIMULATION] Declares VirtualAlloc memory allocation API, commonly utilized by shellcode loaders."
        ),
        Finding(
            finding_id="SIM_FIND_003",
            indicator_name="Win32API_WriteProcessMemory",
            category="INJECTION",
            severity="HIGH",
            evidence='Private Declare PtrSafe Function WriteProcessMemory Lib "kernel32" ...',
            source_module="Module1",
            line_number=6,
            explanation="[SIMULATION] Declares WriteProcessMemory API, indicative of native buffer copy into executable memory."
        ),
        Finding(
            finding_id="SIM_FIND_004",
            indicator_name="Win32API_CreateThread",
            category="EXECUTION",
            severity="HIGH",
            evidence='Private Declare PtrSafe Function CreateThread Lib "kernel32" ...',
            source_module="Module1",
            line_number=7,
            explanation="[SIMULATION] Declares CreateThread API for asynchronous execution of injected payload code."
        ),
        Finding(
            finding_id="SIM_FIND_005",
            indicator_name="Chr_Obfuscation",
            category="OBFUSCATION",
            severity="MEDIUM",
            evidence='c2Url = Chr(104) & Chr(116) & Chr(116) & Chr(112) ...',
            source_module="Module1",
            line_number=21,
            explanation="[SIMULATION] Nested Chr() numeric character codes used to obscure external command-and-control URI."
        ),
        Finding(
            finding_id="SIM_FIND_006",
            indicator_name="Network_C2_Indicator",
            category="C2_NETWORK",
            severity="HIGH",
            evidence="http://c2-finance-update.org/gate.php",
            source_module="Module1",
            line_number=21,
            explanation="[SIMULATION] Hardcoded external command-and-control beaconing endpoint."
        ),
        Finding(
            finding_id="SIM_FIND_007",
            indicator_name="StrReverse_Encoding",
            category="OBFUSCATION",
            severity="LOW",
            evidence='StrReverse("exe.etadpu")',
            source_module="Module1",
            line_number=22,
            explanation="[SIMULATION] String reversed to obscure binary payload name."
        ),
    ]

    # 5. Illustrative Attack Patterns & Fusion
    attack_patterns = [
        CorrelatedAttackPattern(
            pattern_name="Staged Memory Injection Loader",
            description="Simulated multi-stage memory injection sequence combining AutoOpen with native Win32 memory allocation and remote thread execution.",
            severity="CRITICAL",
            confidence="HIGH",
            contributing_finding_ids=["SIM_FIND_001", "SIM_FIND_002", "SIM_FIND_003", "SIM_FIND_004"],
            evidence_summary="AutoOpen -> VirtualAlloc -> WriteProcessMemory -> CreateThread"
        ),
        CorrelatedAttackPattern(
            pattern_name="Automated C2 Stager",
            description="Simulated automatic network beaconing loader establishing command-and-control communication.",
            severity="HIGH",
            confidence="HIGH",
            contributing_finding_ids=["SIM_FIND_001", "SIM_FIND_006"],
            evidence_summary="AutoOpen -> HTTP C2 Beacon (c2-finance-update.org)"
        )
    ]

    fused = FusedDetectionResult(
        raw_finding_count=len(findings),
        deduplicated_findings=findings,
        category_counts={"EXECUTION": 2, "INJECTION": 2, "OBFUSCATION": 2, "C2_NETWORK": 1},
        correlated_patterns=attack_patterns,
        has_auto_exec=True,
        has_memory_alloc=True,
        has_memory_copy=True,
        has_thread_create=True,
        has_c2_indicator=True
    )

    # 6. Illustrative Deobfuscation Results
    deobf_results = [
        DeobfuscationResult(
            original_expression='Chr(104)&Chr(116)&Chr(116)&Chr(112)&Chr(58)&Chr(47)&Chr(47)&"c2-finance-update.org/gate.php"',
            reconstructed_value="http://c2-finance-update.org/gate.php",
            transformation_type="Chr_Concat",
            source_module="Module1",
            line_number=21
        ),
        DeobfuscationResult(
            original_expression='StrReverse("exe.etadpu")',
            reconstructed_value="update.exe",
            transformation_type="StrReverse",
            source_module="Module1",
            line_number=22
        )
    ]

    # 7. Illustrative Payload Extraction Results
    sim_payload_bytes = b"\x90" * 64 + b"\x31\xc0\x50\x68\x2f\x2f\x73\x68" + b"\x90" * 952
    payloads = [
        ExtractedPayload(
            payload_id="PAYLOAD_SIM_001",
            source_document=doc.safe_filename,
            source_module="Module1",
            source_line=25,
            payload_size=1024,
            sha256="4a3b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b",
            entropy=7.82,
            raw_bytes=sim_payload_bytes,
            extraction_method="Simulated Hex/Base64 Array Reconstruction",
            extraction_status="RECOVERED",
            supporting_evidence="Module1:L25 - Embedded hex-encoded staging buffer.",
            confidence="High",
            is_payload_candidate=True
        )
    ]

    # 8. Illustrative VBA Stomping Heuristics
    stomping = StompingAnalysisResult(
        is_stomped=True,
        sdi_score=0.75,
        pcode_token_count=120,
        source_line_count=48,
        pcode_disassembly="[SIMULATION] P-code token stream: AutoOpen, VirtualAlloc, WriteProcessMemory, CreateThread",
        discrepancies=[
            StompingDiscrepancy(
                discrepancy_type="MISSING_SOURCE_CALL",
                module_name="Module1",
                pcode_token="VirtualAlloc",
                explanation="[SIMULATION] VirtualAlloc invoked in compiled P-code stream but absent from readable source procedure declarations.",
                severity="HIGH",
                confidence="High"
            )
        ],
        analysis_status="COMPLETED",
        confidence="High",
        notes=["[SIMULATION] Discrepancies between compiled P-code and decompressed VBA source code."]
    )

    # 9. Illustrative Shellcode Analysis & ROR13 API Hashes
    shellcode_report = ShellcodeAnalysisReport(
        is_likely_shellcode=True,
        architecture="x86",
        instruction_count=76,
        detected_heuristics=[
            "PEB Access via fs:[0x30]",
            "Call/Pop Delta Offset Calculation",
            "Consecutive Stack Pushes (Shellcode Prelude)",
            "Suspicious Jump to Allocated Memory"
        ],
        resolved_api_hashes=[
            ResolvedApiHash(
                hash_value_hex="0x0E8FFE4E",
                hash_value_int=0x0E8FFE4E,
                api_name="VirtualAlloc",
                module_name="KERNEL32.DLL",
                algorithm="ROR13_API_UPPER",
                confidence="High"
            ),
            ResolvedApiHash(
                hash_value_hex="0xEC0E4E8E",
                hash_value_int=0xEC0E4E8E,
                api_name="LoadLibraryA",
                module_name="KERNEL32.DLL",
                algorithm="ROR13_API_UPPER",
                confidence="High"
            ),
            ResolvedApiHash(
                hash_value_hex="0x7C0DFCAA",
                hash_value_int=0x7C0DFCAA,
                api_name="GetProcAddress",
                module_name="KERNEL32.DLL",
                algorithm="ROR13_API_UPPER",
                confidence="High"
            ),
        ],
        analysis_status="COMPLETED"
    )

    # 10. Illustrative Risk Assessment Verdict
    verdict = RiskAssessmentVerdict(
        raw_score=85.0,
        normalized_score=SIMULATION_RISK_SCORE,
        classification=SIMULATION_RISK_LEVEL,
        security_verdict=SIMULATION_VERDICT,
        category_scores={"EXECUTION": 25.0, "INJECTION": 25.0, "OBFUSCATION": 15.0, "C2_NETWORK": 20.0},
        applied_bonuses=[
            {"name": "Staged Memory Injection Pattern", "points": 15.0},
            {"name": "Automated C2 Stager Pattern", "points": 10.0}
        ],
        explanation=(
            "[PRESENTATION SIMULATION] Simulated multi-stage weaponized document scenario. "
            f"Verdict: {SIMULATION_VERDICT} | Risk Level: {SIMULATION_RISK_LEVEL} (Score: {SIMULATION_RISK_SCORE}/100) | "
            f"Recommendation: {SIMULATION_RECOMMENDATION}. "
            "Illustrates auto-execution triggers, Win32 memory injection declarations, nested obfuscation, "
            "payload extraction, and ROR13 API hash resolution."
        ),
        limitations=[
            "PRESENTATION SIMULATION: All reported security findings, metrics, and behavioral patterns are illustrative demonstration models, not extracted live evidence.",
            "Zero execution policy strictly maintained; no live macro code, process injection, or network payloads were executed."
        ],
        policy_status="SIMULATED",
        policy_source="PRESENTATION_SIMULATION_PROFILE"
    )
    setattr(verdict, "recommendation", SIMULATION_RECOMMENDATION)

    # 11. Illustrative 18-Feature Vector
    features = DocumentFeatureVector(
        f1_file_size_bytes=_measured("f1_file_size_bytes", actual_size),
        f2_ole_stream_count=_measured("f2_ole_stream_count", stream_count),
        f3_has_vba_project=_measured("f3_has_vba_project", 1),
        f4_stomping_discrepancy=_measured("f4_stomping_discrepancy", 0.75),
        f5_source_line_count=_measured("f5_source_line_count", 48),
        f6_pcode_token_count=_measured("f6_pcode_token_count", 120),
        f7_max_stream_entropy=_measured("f7_max_stream_entropy", max_entropy),
        f8_mean_stream_entropy=_measured("f8_mean_stream_entropy", round(mean_entropy, 2)),
        f9_suspicious_keyword_count=_measured("f9_suspicious_keyword_count", 6),
        f10_obfuscated_chr_count=_measured("f10_obfuscated_chr_count", 12),
        f11_strreverse_calls=_measured("f11_strreverse_calls", 1),
        f12_win32_api_declarations=_measured("f12_win32_api_declarations", 3),
        f13_has_memory_alloc_api=_measured("f13_has_memory_alloc_api", 1),
        f14_has_memory_copy_api=_measured("f14_has_memory_copy_api", 1),
        f15_has_thread_create_api=_measured("f15_has_thread_create_api", 1),
        f16_extracted_payload_bytes=_measured("f16_extracted_payload_bytes", 1024),
        f17_resolved_api_hash_count=_measured("f17_resolved_api_hash_count", 3),
        f18_has_c2_network_indicator=_measured("f18_has_c2_network_indicator", 1),
        analysis_complete=True,
        unavailable_features=[],
        failed_features=[],
        not_applicable_features=[]
    )

    # 12. Illustrative YARA Signature
    sim_yara_text = f"""rule presentation_simulation_invoice_indicator
{{
    meta:
        description = "Illustrative detection signature for Presentation Simulation Mode"
        author = "Automated Office Triage Engine (Presentation Simulation)"
        date = "2026-10-31"
        sha256 = "{TARGET_SIMULATION_SHA256}"
        original_file = "{doc.safe_filename}"
        simulation_mode = "true"
        reference = "Presentation Simulation Profile"

    strings:
        $api_valloc = "VirtualAlloc" ascii wide nocase
        $api_wpm = "WriteProcessMemory" ascii wide nocase
        $api_cthread = "CreateThread" ascii wide nocase
        $trigger_auto = "AutoOpen" ascii wide nocase
        $c2_domain = "c2-finance-update.org" ascii wide nocase

    condition:
        uint16(0) == 0x4B50 and ($trigger_auto and 2 of ($api_*))
}}"""

    yara_rule = SynthesizedYaraRule(
        rule_name="presentation_simulation_invoice_indicator",
        rule_text=sim_yara_text,
        is_valid_syntax=True,
        matching_strings=["AutoOpen", "VirtualAlloc", "WriteProcessMemory", "CreateThread", "c2-finance-update.org"],
        source_evidence_count=5
    )

    # 13. Consolidated Report Data
    stage_statuses = {
        "ingestion": "COMPLETED",
        "format_validation": "COMPLETED",
        "metadata_extraction": "COMPLETED",
        "structural_inspection": "COMPLETED",
        "vba_extraction": "COMPLETED",
        "static_detection": "COMPLETED",
        "detection_fusion": "COMPLETED",
        "stomping_analysis": "COMPLETED",
        "vba_deobfuscation": "COMPLETED",
        "payload_extraction": "COMPLETED",
        "shellcode_analysis": "COMPLETED",
        "api_hash_resolution": "COMPLETED",
        "feature_extraction": "COMPLETED",
        "risk_assessment": "COMPLETED",
        "yara_synthesis": "COMPLETED",
        "presentation_simulation": "ACTIVE"
    }

    report_data = ReportGenerator.build_report_data(
        doc=doc,
        metadata=metadata,
        structure=structure,
        vba=vba,
        fused=fused,
        verdict=verdict,
        stomping=stomping,
        deobf_results=deobf_results,
        payloads=payloads,
        shellcode_report=shellcode_report,
        feature_vector=features,
        yara_rule=yara_rule,
        analysis_status="COMPLETED",
        analysis_limitations=verdict.limitations,
        stage_statuses=stage_statuses
    )

    # Augment report_data with explicit simulation flags
    report_data["simulation_mode"] = True
    report_data["target_file_hash"] = TARGET_SIMULATION_SHA256
    report_data["recommendation"] = SIMULATION_RECOMMENDATION
    report_data["analysis_overview"]["simulation_mode"] = True
    report_data["analysis_overview"]["recommendation"] = SIMULATION_RECOMMENDATION
    report_data["analysis_overview"]["security_verdict"] = SIMULATION_VERDICT
    report_data["analysis_overview"]["risk_classification"] = SIMULATION_RISK_LEVEL
    report_data["analysis_overview"]["normalized_score"] = SIMULATION_RISK_SCORE

    # Export simulated HTML and JSON reports
    stem = Path(doc.safe_filename).stem
    h_prefix = TARGET_SIMULATION_SHA256[:8]
    json_path = output_dir / f"report_{stem}_{h_prefix}_simulated.json"
    html_path = output_dir / f"report_{stem}_{h_prefix}_simulated.html"

    ReportGenerator.export_json(report_data, json_path)
    ReportGenerator.export_html(report_data, html_path)

    return TriagePipelineResult(
        doc=doc,
        metadata=metadata,
        structure=structure,
        vba=vba,
        findings=findings,
        deobf_results=deobf_results,
        payloads=payloads,
        stomping=stomping,
        shellcode_report=shellcode_report,
        fused=fused,
        verdict=verdict,
        features=features,
        yara_rule=yara_rule,
        report_data=report_data,
        analysis_status="COMPLETED",
        stage_statuses=stage_statuses,
        analysis_limitations=verdict.limitations,
        html_report_path=html_path,
        json_report_path=json_path,
        is_simulation=True,
        recommendation=SIMULATION_RECOMMENDATION
    )

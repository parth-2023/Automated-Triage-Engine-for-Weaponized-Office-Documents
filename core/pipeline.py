"""
End-to-End Triage Pipeline Orchestrator.
Connects all analysis phases from file ingestion through to report synthesis
and structured verdict generation.

Analysis status codes:
  COMPLETED       - All stages ran without error.
  PARTIAL         - Some stages ran; others were skipped due to missing deps or format.
  FAILED          - A critical stage failed.
  UNSUPPORTED     - File format not supported.
  INVALID_INPUT   - File is empty, oversized, or corrupt.
"""

from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

from core.ingestion import IngestionManager, IngestedDocument
from core.metadata import MetadataExtractor
from core.document_inspector import DocumentInspector, StructuralInspectionResult
from core.vba_extractor import VBAExtractor, VBAExtractionResult
from core.static_analyzer import StaticAnalyzer, Finding
from core.deobfuscator import RestrictedVbaDeobfuscator, DeobfuscationResult
from core.payload_extractor import PayloadExtractor, ExtractedPayload
from core.stomping_detector import StompingDetector, StompingAnalysisResult
from core.shellcode_analyzer import ShellcodeAnalyzer, ShellcodeAnalysisReport
from core.fusion import DetectionFusionEngine, FusedDetectionResult
from core.risk_engine import RiskEngine, RiskAssessmentVerdict
from core.feature_extractor import FeatureExtractor, DocumentFeatureVector, FeatureState
from core.yara_synthesizer import YaraRuleSynthesizer, SynthesizedYaraRule
from core.report_generator import ReportGenerator


@dataclass
class TriagePipelineResult:
    """Consolidated pipeline result encapsulating all phase outputs."""
    doc: IngestedDocument
    metadata: Dict[str, Any]
    structure: StructuralInspectionResult
    vba: VBAExtractionResult
    findings: List[Finding]
    deobf_results: List[DeobfuscationResult]
    payloads: List[ExtractedPayload]
    stomping: StompingAnalysisResult
    shellcode_report: ShellcodeAnalysisReport
    fused: FusedDetectionResult
    verdict: RiskAssessmentVerdict
    features: DocumentFeatureVector
    yara_rule: SynthesizedYaraRule
    report_data: Dict[str, Any]
    analysis_status: str = "COMPLETED"      # COMPLETED, PARTIAL, FAILED, UNSUPPORTED, INVALID_INPUT
    analysis_limitations: List[str] = None   # populated post-init
    html_report_path: Optional[Path] = None
    json_report_path: Optional[Path] = None

    def __post_init__(self):
        if self.analysis_limitations is None:
            self.analysis_limitations = []


class TriagePipeline:
    """Autonomous static analysis pipeline for Microsoft Office documents."""

    def __init__(self, policy_path: Optional[Path] = None, output_dir: Optional[Path] = None):
        self.risk_engine = RiskEngine(policy_path)
        self.shellcode_analyzer = ShellcodeAnalyzer()
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze_file(self, file_path_or_bytes: Any, filename: Optional[str] = None) -> TriagePipelineResult:
        """Execute full end-to-end triage."""
        limitations: List[str] = []

        with IngestionManager() as mgr:
            # 1. Ingestion
            doc = mgr.ingest_file(file_path_or_bytes, original_name=filename)

            # If invalid or corrupt signature, short-circuit safely
            if not doc.is_valid:
                fmt = doc.detected_format
                if fmt in ("EMPTY", "OVERSIZED"):
                    analysis_status = "INVALID_INPUT"
                elif fmt == "UNSUPPORTED":
                    analysis_status = "UNSUPPORTED"
                else:
                    analysis_status = "INVALID_INPUT"

                empty_struct = StructuralInspectionResult(doc.detected_format, 0, is_corrupt=True)
                empty_vba = VBAExtractionResult(False, 0, 0, [])
                empty_fused = DetectionFusionEngine.fuse([])
                verdict = self.risk_engine.evaluate(empty_fused, is_valid_format=False,
                                                    analysis_status=analysis_status)
                empty_stomping = StompingAnalysisResult(False, 0.0, 0, 0, "", analysis_status="NOT_PERFORMED")
                empty_shellcode = ShellcodeAnalysisReport(False, "UNKNOWN", 0, analysis_status="NO_CANDIDATE")
                empty_features = FeatureExtractor.extract_features(
                    doc, empty_struct, empty_vba, empty_fused,
                    stomping_sdi=None, stomping_status=FeatureState.NOT_APPLICABLE,
                    stomping_note="Format validation failed.",
                    pcode_tokens=None, pcode_status=FeatureState.NOT_APPLICABLE,
                    pcode_note="Format validation failed.",
                    payload_bytes=None, payload_status=FeatureState.NOT_APPLICABLE,
                    payload_note="Format validation failed.",
                    resolved_api_hashes=None, api_hash_status=FeatureState.NOT_APPLICABLE,
                    api_hash_note="Format validation failed.",
                )
                synth_yara = YaraRuleSynthesizer.synthesize_rule(doc, empty_fused, [], [])
                report_data = ReportGenerator.build_report_data(
                    doc, {}, empty_struct, empty_vba, empty_fused, verdict, empty_stomping,
                    [], [], empty_shellcode, empty_features, synth_yara,
                    analysis_status=analysis_status
                )
                return TriagePipelineResult(
                    doc=doc,
                    metadata={},
                    structure=empty_struct,
                    vba=empty_vba,
                    findings=[],
                    deobf_results=[],
                    payloads=[],
                    stomping=empty_stomping,
                    shellcode_report=empty_shellcode,
                    fused=empty_fused,
                    verdict=verdict,
                    features=empty_features,
                    yara_rule=synth_yara,
                    report_data=report_data,
                    analysis_status=analysis_status,
                    analysis_limitations=[doc.error_message] if doc.error_message else [],
                )

            # 2. Metadata Extraction
            metadata = MetadataExtractor.extract(doc.file_path, doc.detected_format)

            # 3. Structural Inspection
            structure = DocumentInspector.inspect(doc.file_path, doc.detected_format)

            if structure.is_corrupt:
                empty_vba = VBAExtractionResult(False, 0, 0, [])
                empty_fused = DetectionFusionEngine.fuse([], structure.anomalies)
                verdict = self.risk_engine.evaluate(empty_fused, is_valid_format=True, is_corrupt=True,
                                                    analysis_status="INVALID_INPUT")
                empty_stomping = StompingAnalysisResult(False, 0.0, 0, 0, "", analysis_status="NOT_PERFORMED")
                empty_shellcode = ShellcodeAnalysisReport(False, "UNKNOWN", 0, analysis_status="NO_CANDIDATE")
                empty_features = FeatureExtractor.extract_features(
                    doc, structure, empty_vba, empty_fused,
                    stomping_sdi=None, stomping_status=FeatureState.NOT_APPLICABLE,
                    stomping_note="Corrupt document.",
                    pcode_tokens=None, pcode_status=FeatureState.NOT_APPLICABLE,
                    payload_bytes=None, payload_status=FeatureState.NOT_APPLICABLE,
                    resolved_api_hashes=None, api_hash_status=FeatureState.NOT_APPLICABLE,
                )
                synth_yara = YaraRuleSynthesizer.synthesize_rule(doc, empty_fused, [], [])
                report_data = ReportGenerator.build_report_data(
                    doc, metadata, structure, empty_vba, empty_fused, verdict, empty_stomping,
                    [], [], empty_shellcode, empty_features, synth_yara,
                    analysis_status="INVALID_INPUT"
                )
                return TriagePipelineResult(
                    doc=doc,
                    metadata=metadata,
                    structure=structure,
                    vba=empty_vba,
                    findings=[],
                    deobf_results=[],
                    payloads=[],
                    stomping=empty_stomping,
                    shellcode_report=empty_shellcode,
                    fused=empty_fused,
                    verdict=verdict,
                    features=empty_features,
                    yara_rule=synth_yara,
                    report_data=report_data,
                    analysis_status="INVALID_INPUT",
                    analysis_limitations=["Document container is corrupt; deep analysis was not possible."],
                )

            # 4. VBA Extraction
            vba = VBAExtractor.extract_vba(doc.file_path)

            # 5. Static Analysis
            findings = StaticAnalyzer.analyze_vba_result(vba)

            # 6. AST & Rule Deobfuscation
            deobf_results: List[DeobfuscationResult] = []
            for mod in vba.modules:
                deobf_results.extend(RestrictedVbaDeobfuscator.analyze_module(mod.code, mod.module_name))

            # 7. Payload Extraction — from original VBA AND deobfuscation output
            payloads = PayloadExtractor.extract_all(vba, doc.safe_filename, deobf_results=deobf_results)
            total_payload_bytes = sum(p.payload_size for p in payloads)
            payload_status = FeatureState.MEASURED if vba.has_macros else FeatureState.NOT_DETECTED
            payload_note = "" if vba.has_macros else "No VBA macros present; payload extraction not applicable."

            # 8. VBA Stomping Detection
            stomping = StompingDetector.analyze(doc.file_path, vba)
            stomping_sdi_val: Optional[float] = None
            pcode_tok_val: Optional[int] = None

            if stomping.analysis_status == "COMPLETED":
                stomping_sdi_val = stomping.sdi_score
                pcode_tok_val = stomping.pcode_token_count
                stomping_feat_status = FeatureState.MEASURED if stomping_sdi_val > 0 else FeatureState.NOT_DETECTED
                pcode_feat_status = FeatureState.MEASURED if pcode_tok_val > 0 else FeatureState.NOT_DETECTED
                stomping_note = ""
                pcode_note = ""
            elif stomping.analysis_status == "NOT_PERFORMED":
                stomping_feat_status = FeatureState.NOT_APPLICABLE
                pcode_feat_status = FeatureState.NOT_APPLICABLE
                stomping_note = "No macros present."
                pcode_note = "No macros present."
                limitations.append("VBA stomping analysis: no macros present.")
            else:  # PARTIAL
                stomping_feat_status = FeatureState.UNAVAILABLE
                pcode_feat_status = FeatureState.UNAVAILABLE
                stomping_note = "; ".join(stomping.notes)
                pcode_note = "; ".join(stomping.notes)
                limitations.append(f"VBA stomping analysis partial: {stomping_note}")

            # 9. Shellcode Analysis on Extracted Payloads
            shellcode_report = ShellcodeAnalysisReport(False, "UNKNOWN", 0, analysis_status="NO_CANDIDATE")
            api_hash_val: Optional[int] = None
            api_hash_status = FeatureState.NOT_APPLICABLE
            api_hash_note = "No payload candidates."

            if payloads:
                api_hash_status = FeatureState.NOT_DETECTED
                api_hash_val = 0
                for payload in payloads:
                    cand_report = self.shellcode_analyzer.analyze_buffer(payload.raw_bytes)
                    if cand_report.is_likely_shellcode:
                        shellcode_report = cand_report
                        findings.append(Finding(
                            finding_id=f"SHELLCODE_{payload.payload_id}",
                            indicator_name="EmbeddedShellcode",
                            category="PAYLOAD",
                            severity="CRITICAL",
                            evidence=f"Shellcode heuristics matched: {', '.join(cand_report.detected_heuristics[:2])}",
                            source_module=payload.source_module,
                            line_number=payload.source_line,
                            explanation="Candidate binary payload exhibits shellcode execution characteristics."
                        ))
                    resolved_count = len(cand_report.resolved_api_hashes)
                    if resolved_count > 0:
                        api_hash_val = (api_hash_val or 0) + resolved_count
                        api_hash_status = FeatureState.MEASURED

                if api_hash_val == 0:
                    api_hash_note = "Shellcode analysis completed; no known API hashes resolved."
                    api_hash_status = FeatureState.NOT_DETECTED

            if shellcode_report.analysis_status == "FAILED":
                limitations.append(f"Shellcode analysis failed: {shellcode_report.error}")

            # 10. Detection Fusion
            fused = DetectionFusionEngine.fuse(findings, structure.anomalies)

            # 11. Determine overall analysis status
            overall_status = "COMPLETED" if not limitations else "PARTIAL"

            # 12. Risk Scoring (pass analysis status so incomplete analysis is flagged)
            verdict = self.risk_engine.evaluate(
                fused,
                is_valid_format=True,
                is_corrupt=False,
                analysis_status=overall_status,
                incomplete_features=limitations
            )

            # 13. 18-Feature Representation
            features = FeatureExtractor.extract_features(
                doc=doc,
                structure=structure,
                vba=vba,
                fused=fused,
                stomping_sdi=stomping_sdi_val,
                stomping_status=stomping_feat_status,
                stomping_note=stomping_note,
                pcode_tokens=pcode_tok_val,
                pcode_status=pcode_feat_status,
                pcode_note=pcode_note,
                payload_bytes=total_payload_bytes if payloads else None,
                payload_status=payload_status,
                payload_note=payload_note,
                resolved_api_hashes=api_hash_val,
                api_hash_status=api_hash_status,
                api_hash_note=api_hash_note,
            )

            # 14. YARA Rule Synthesis
            yara_rule = YaraRuleSynthesizer.synthesize_rule(doc, fused, deobf_results, payloads)

            # 15. Report Generation
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
                analysis_status=overall_status,
                analysis_limitations=limitations,
            )

            # Save HTML and JSON reports
            stem = Path(doc.safe_filename).stem
            json_path = self.output_dir / f"report_{stem}_{doc.hashes['sha256'][:8]}.json"
            html_path = self.output_dir / f"report_{stem}_{doc.hashes['sha256'][:8]}.html"

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
                analysis_status=overall_status,
                analysis_limitations=limitations,
                html_report_path=html_path,
                json_report_path=json_path,
            )

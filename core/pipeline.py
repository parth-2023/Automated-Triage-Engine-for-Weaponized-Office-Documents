"""
End-to-End Triage Pipeline Orchestrator.
Connects all analysis phases from file ingestion through to report synthesis
and structured verdict generation.
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
from core.feature_extractor import FeatureExtractor, DocumentFeatureVector
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
    html_report_path: Optional[Path] = None
    json_report_path: Optional[Path] = None


class TriagePipeline:
    """Autonomous static analysis pipeline for Microsoft Office documents."""

    def __init__(self, policy_path: Optional[Path] = None, output_dir: Optional[Path] = None):
        self.risk_engine = RiskEngine(policy_path)
        self.shellcode_analyzer = ShellcodeAnalyzer()
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze_file(self, file_path_or_bytes: Any, filename: Optional[str] = None) -> TriagePipelineResult:
        """Execute full end-to-end triage."""
        with IngestionManager() as mgr:
            # 1. Ingestion
            doc = mgr.ingest_file(file_path_or_bytes, original_name=filename)

            # If invalid or corrupt signature, short-circuit safely
            if not doc.is_valid:
                empty_struct = StructuralInspectionResult(doc.detected_format, 0, is_corrupt=True)
                empty_vba = VBAExtractionResult(False, 0, 0, [])
                empty_fused = DetectionFusionEngine.fuse([])
                verdict = self.risk_engine.evaluate(empty_fused, is_valid_format=False)
                empty_stomping = StompingAnalysisResult(False, 0.0, 0, 0, "", analysis_status="NOT_PERFORMED")
                empty_shellcode = ShellcodeAnalysisReport(False, "UNKNOWN", 0, analysis_status="NO_CANDIDATE")
                empty_features = FeatureExtractor.extract_features(doc, empty_struct, empty_vba, empty_fused)
                synth_yara = YaraRuleSynthesizer.synthesize_rule(doc, empty_fused, [], [])
                report_data = ReportGenerator.build_report_data(
                    doc, {}, empty_struct, empty_vba, empty_fused, verdict, empty_stomping,
                    [], [], empty_shellcode, empty_features, synth_yara
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
                    report_data=report_data
                )

            # 2. Metadata Extraction
            metadata = MetadataExtractor.extract(doc.file_path, doc.detected_format)

            # 3. Structural Inspection
            structure = DocumentInspector.inspect(doc.file_path, doc.detected_format)

            # 4. VBA Extraction
            vba = VBAExtractor.extract_vba(doc.file_path)

            # 5. Static Analysis
            findings = StaticAnalyzer.analyze_vba_result(vba)

            # 6. AST & Rule Deobfuscation
            deobf_results: List[DeobfuscationResult] = []
            for mod in vba.modules:
                deobf_results.extend(RestrictedVbaDeobfuscator.analyze_module(mod.code, mod.module_name))

            # 7. Payload Extraction
            payloads = PayloadExtractor.extract_all(vba, doc.safe_filename)

            # 8. VBA Stomping Detection
            stomping = StompingDetector.analyze(doc.file_path, vba)

            # 9. Shellcode Analysis on Extracted Payloads
            shellcode_report = ShellcodeAnalysisReport(False, "UNKNOWN", 0, analysis_status="NO_CANDIDATE")
            total_payload_bytes = sum(p.payload_size for p in payloads)

            for payload in payloads:
                cand_report = self.shellcode_analyzer.analyze_buffer(payload.raw_bytes)
                if cand_report.is_likely_shellcode:
                    shellcode_report = cand_report
                    # Add finding for shellcode
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

            # 10. Detection Fusion
            fused = DetectionFusionEngine.fuse(findings, structure.anomalies)

            # 11. Risk Scoring
            verdict = self.risk_engine.evaluate(fused, is_valid_format=True, is_corrupt=structure.is_corrupt)

            # 12. 18-Feature Representation
            resolved_hashes_count = len(shellcode_report.resolved_api_hashes)
            features = FeatureExtractor.extract_features(
                doc=doc,
                structure=structure,
                vba=vba,
                fused=fused,
                stomping_sdi=stomping.sdi_score,
                pcode_tokens=stomping.pcode_token_count,
                payload_bytes=total_payload_bytes,
                resolved_api_hashes=resolved_hashes_count
            )

            # 13. YARA Rule Synthesis
            yara_rule = YaraRuleSynthesizer.synthesize_rule(doc, fused, deobf_results, payloads)

            # 14. Report Generation
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
                yara_rule=yara_rule
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
                html_report_path=html_path,
                json_report_path=json_path
            )

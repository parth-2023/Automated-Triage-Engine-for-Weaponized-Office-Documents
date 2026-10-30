"""
Analyst Report Generation Module.
Produces comprehensive, self-contained HTML reports and structured JSON reports
incorporating all phases of static triage evidence, risk calculations, and limitations.
"""

import json
from pathlib import Path
from dataclasses import asdict
from typing import Dict, Any, List

from core.ingestion import IngestedDocument
from core.document_inspector import StructuralInspectionResult
from core.vba_extractor import VBAExtractionResult
from core.fusion import FusedDetectionResult
from core.risk_engine import RiskAssessmentVerdict
from core.stomping_detector import StompingAnalysisResult
from core.deobfuscator import DeobfuscationResult
from core.payload_extractor import ExtractedPayload
from core.shellcode_analyzer import ShellcodeAnalysisReport
from core.feature_extractor import DocumentFeatureVector
from core.yara_synthesizer import SynthesizedYaraRule


class ReportGenerator:
    """Generates structured JSON and professional standalone HTML reports for security analysts."""

    @classmethod
    def build_report_data(
        cls,
        doc: IngestedDocument,
        metadata: Dict[str, Any],
        structure: StructuralInspectionResult,
        vba: VBAExtractionResult,
        fused: FusedDetectionResult,
        verdict: RiskAssessmentVerdict,
        stomping: StompingAnalysisResult,
        deobf_results: List[DeobfuscationResult],
        payloads: List[ExtractedPayload],
        shellcode_report: ShellcodeAnalysisReport,
        feature_vector: DocumentFeatureVector,
        yara_rule: SynthesizedYaraRule,
    ) -> Dict[str, Any]:
        """Consolidate all pipeline artifacts into a single report dictionary."""
        return {
            "sample_identity": {
                "original_filename": doc.original_filename,
                "safe_filename": doc.safe_filename,
                "file_size_bytes": doc.file_size_bytes,
                "hashes": doc.hashes,
                "file_entropy": doc.file_entropy,
                "detected_format": doc.detected_format,
                "extension": doc.extension,
                "is_valid": doc.is_valid,
                "validation_notes": doc.validation_notes,
            },
            "document_metadata": metadata,
            "structural_analysis": {
                "container_type": structure.container_type,
                "stream_count": structure.stream_count,
                "has_vba_project": structure.has_vba_project,
                "vba_project_location": structure.vba_project_location,
                "max_stream_entropy": structure.max_stream_entropy,
                "mean_stream_entropy": structure.mean_stream_entropy,
                "anomalies": structure.anomalies,
                "streams": [
                    {
                        "name": s.name,
                        "size_bytes": s.size_bytes,
                        "entropy": s.entropy,
                        "storage_path": s.storage_path,
                        "is_vba_related": s.is_vba_related,
                        "is_suspicious_entropy": s.is_suspicious_entropy,
                    }
                    for s in structure.streams
                ],
            },
            "vba_extraction": {
                "has_macros": vba.has_macros,
                "module_count": vba.module_count,
                "total_line_count": vba.total_line_count,
                "modules": [
                    {
                        "module_name": m.module_name,
                        "line_count": m.line_count,
                        "procedures": m.procedures,
                        "code_preview": m.code[:500] if m.code else "",
                    }
                    for m in vba.modules
                ],
            },
            "static_detection_and_fusion": {
                "raw_finding_count": fused.raw_finding_count,
                "deduplicated_findings": [
                    {
                        "finding_id": f.finding_id,
                        "indicator_name": f.indicator_name,
                        "category": f.category,
                        "severity": f.severity,
                        "evidence": f.evidence,
                        "source_module": f.source_module,
                        "line_number": f.line_number,
                        "explanation": f.explanation,
                    }
                    for f in fused.deduplicated_findings
                ],
                "correlated_patterns": [
                    {
                        "pattern_name": p.pattern_name,
                        "severity": p.severity,
                        "confidence": p.confidence,
                        "description": p.description,
                        "evidence_summary": p.evidence_summary,
                    }
                    for p in fused.correlated_patterns
                ],
            },
            "stomping_analysis": {
                "is_stomped": stomping.is_stomped,
                "sdi_score": stomping.sdi_score,
                "pcode_token_count": stomping.pcode_token_count,
                "analysis_status": stomping.analysis_status,
                "discrepancies": [
                    {
                        "type": d.discrepancy_type,
                        "token": d.pcode_token,
                        "explanation": d.explanation,
                    }
                    for d in stomping.discrepancies
                ],
            },
            "deobfuscation": [
                {
                    "original": d.original_expression,
                    "reconstructed": d.reconstructed_value,
                    "transformation": d.transformation_type,
                    "module": d.source_module,
                    "line": d.line_number,
                }
                for d in deobf_results
            ],
            "extracted_payloads": [
                {
                    "id": p.payload_id,
                    "size_bytes": p.payload_size,
                    "sha256": p.sha256,
                    "entropy": p.entropy,
                    "method": p.extraction_method,
                    "status": p.extraction_status,
                    "evidence": p.supporting_evidence,
                }
                for p in payloads
            ],
            "shellcode_analysis": {
                "is_likely_shellcode": shellcode_report.is_likely_shellcode,
                "architecture": shellcode_report.architecture,
                "instruction_count": shellcode_report.instruction_count,
                "heuristics": shellcode_report.detected_heuristics,
                "resolved_api_hashes": [
                    {
                        "hex": r.hash_value_hex,
                        "api": r.api_name,
                        "module": r.module_name,
                    }
                    for r in shellcode_report.resolved_api_hashes
                ],
                "disassembly_preview": [
                    f"0x{insn.offset:04X}: {insn.mnemonic} {insn.op_str}"
                    for insn in shellcode_report.disassembly[:25]
                ],
            },
            "feature_vector_18d": feature_vector.to_dict(),
            "synthesized_yara_rule": {
                "rule_name": yara_rule.rule_name,
                "is_valid_syntax": yara_rule.is_valid_syntax,
                "rule_text": yara_rule.rule_text,
            },
            "risk_assessment": {
                "raw_score": verdict.raw_score,
                "normalized_score": verdict.normalized_score,
                "classification": verdict.classification,
                "category_scores": verdict.category_scores,
                "applied_bonuses": verdict.applied_bonuses,
                "explanation": verdict.explanation,
                "limitations": verdict.limitations,
            },
        }

    @classmethod
    def export_json(cls, report_data: Dict[str, Any], output_path: Path) -> Path:
        """Save report data as formatted JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        return output_path

    @classmethod
    def export_html(cls, report_data: Dict[str, Any], output_path: Path) -> Path:
        """Render a self-contained, professional HTML report."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        verdict = report_data["risk_assessment"]
        ident = report_data["sample_identity"]
        struct = report_data["structural_analysis"]
        fused = report_data["static_detection_and_fusion"]
        features = report_data["feature_vector_18d"]
        yara = report_data["synthesized_yara_rule"]

        # Color mapping for classification badge
        badge_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#16a34a",
            "INCONCLUSIVE": "#6b7280",
            "UNSUPPORTED FORMAT": "#9ca3af",
        }
        badge_color = badge_colors.get(verdict["classification"], "#4b5563")

        findings_rows = ""
        for f in fused["deduplicated_findings"]:
            findings_rows += f"""
            <tr>
                <td><span class="badge {f['severity'].lower()}">{f['severity']}</span></td>
                <td><strong>{f['indicator_name']}</strong></td>
                <td>{f['category']}</td>
                <td>{f['source_module']} (L{f['line_number'] or 'N/A'})</td>
                <td><code>{f['evidence']}</code></td>
                <td>{f['explanation']}</td>
            </tr>
            """

        streams_rows = ""
        for s in struct["streams"][:15]:
            streams_rows += f"""
            <tr>
                <td>{s['name']}</td>
                <td>{s['storage_path']}</td>
                <td>{s['size_bytes']} bytes</td>
                <td>{s['entropy']}</td>
                <td>{'Yes' if s['is_vba_related'] else 'No'}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Office Document Malware Triage Report - {ident['safe_filename']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: #1e293b; padding: 24px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #334155; }}
        .badge {{ padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 0.85rem; display: inline-block; }}
        .badge.critical {{ background: #dc2626; color: white; }}
        .badge.high {{ background: #ea580c; color: white; }}
        .badge.medium {{ background: #d97706; color: white; }}
        .badge.low {{ background: #16a34a; color: white; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }}
        .card h3 {{ margin-top: 0; color: #94a3b8; font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .card .value {{ font-size: 1.6rem; font-weight: bold; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
        th {{ background: #0f172a; color: #94a3b8; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #f43f5e; font-family: monospace; }}
        pre {{ background: #0f172a; padding: 14px; border-radius: 8px; overflow-x: auto; color: #a5f3fc; font-size: 0.85rem; border: 1px solid #334155; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1 style="margin: 0 0 8px 0;">Office Document Malware Triage Report</h1>
                <div style="color: #94a3b8;">Sample: <strong>{ident['original_filename']}</strong></div>
            </div>
            <div style="text-align: right;">
                <span class="badge" style="background-color: {badge_color}; font-size: 1.2rem; padding: 10px 20px;">
                    {verdict['classification']} (Score: {verdict['normalized_score']}/100)
                </span>
            </div>
        </div>
        <p style="margin: 16px 0 0 0; color: #cbd5e1;">{verdict['explanation']}</p>
    </div>

    <div class="grid">
        <div class="card">
            <h3>SHA-256 Digest</h3>
            <div style="font-family: monospace; font-size: 0.85rem; word-break: break-all; color: #38bdf8;">
                {ident['hashes']['sha256']}
            </div>
        </div>
        <div class="card">
            <h3>File Size & Format</h3>
            <div class="value">{ident['file_size_bytes']} B</div>
            <div style="color: #94a3b8; font-size: 0.85rem;">Format: {ident['detected_format']} | Entropy: {ident['file_entropy']}</div>
        </div>
        <div class="card">
            <h3>VBA Macros & SDI</h3>
            <div class="value">{'Present' if report_data['vba_extraction']['has_macros'] else 'None'}</div>
            <div style="color: #94a3b8; font-size: 0.85rem;">Lines: {report_data['vba_extraction']['total_line_count']} | SDI: {report_data['stomping_analysis']['sdi_score']}</div>
        </div>
        <div class="card">
            <h3>Findings & Patterns</h3>
            <div class="value">{len(fused['deduplicated_findings'])}</div>
            <div style="color: #94a3b8; font-size: 0.85rem;">Correlated Attack Patterns: {len(fused['correlated_patterns'])}</div>
        </div>
    </div>

    <h2>Static Detections & Evidence</h2>
    <table>
        <thead>
            <tr><th>Severity</th><th>Indicator</th><th>Category</th><th>Source</th><th>Evidence Snippet</th><th>Explanation</th></tr>
        </thead>
        <tbody>
            {findings_rows if findings_rows else '<tr><td colspan="6" style="text-align:center;">No suspicious static indicators detected.</td></tr>'}
        </tbody>
    </table>

    <h2>Synthesized YARA Detection Signature</h2>
    <pre>{yara['rule_text']}</pre>

    <h2>Document Streams & Entropy</h2>
    <table>
        <thead>
            <tr><th>Stream Name</th><th>Path</th><th>Size</th><th>Entropy</th><th>VBA Related</th></tr>
        </thead>
        <tbody>
            {streams_rows}
        </tbody>
    </table>

    <h2>Analysis Limitations & Caveats</h2>
    <ul>
        {''.join(f'<li>{lim}</li>' for lim in verdict['limitations'])}
        <li>Static triage only. No live macro execution or process injection was performed.</li>
    </ul>
</div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path

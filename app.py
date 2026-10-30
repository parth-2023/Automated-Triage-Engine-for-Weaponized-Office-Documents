"""
Automated Triage Engine for Weaponized Office Documents
Gradio Web Application & Analyst Dashboard
"""

import os
import json
import html
import gradio as gr
from pathlib import Path
from typing import Tuple, Any

from core.pipeline import TriagePipeline, TriagePipelineResult


pipeline = TriagePipeline()


def analyze_document(file_obj) -> Tuple[Any, ...]:
    """
    Gradio callback handler: runs full triage pipeline on uploaded file.
    """
    if file_obj is None:
        return (
            "### Please upload a valid Office document (.doc, .docm, .xls, .xlsm) to begin triage.",
            [], [], "", [], [], [], [], [], [], "", None, None
        )

    file_path = file_obj.name if hasattr(file_obj, "name") else str(file_obj)
    original_name = Path(file_path).name

    # Run complete analysis pipeline
    res: TriagePipelineResult = pipeline.analyze_file(file_path, filename=original_name)

    # 1. Executive Summary HTML (safely escaped)
    verdict = res.verdict
    badge_colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#f59e0b",
        "LOW": "#10b981",
        "PARTIAL": "#eab308",
        "INCONCLUSIVE": "#6b7280",
        "UNSUPPORTED": "#9ca3af",
        "UNSUPPORTED FORMAT": "#9ca3af",
    }
    b_color = badge_colors.get(verdict.classification, "#64748b")

    safe_orig_name = html.escape(str(res.doc.original_filename or "Unknown"))
    safe_format = html.escape(str(res.doc.detected_format or "Unknown"))
    safe_classification = html.escape(str(verdict.classification or "Unknown"))
    safe_explanation = html.escape(str(verdict.explanation or ""))
    safe_status = html.escape(str(res.analysis_status or "COMPLETED"))
    sec_verdict = html.escape(str(getattr(verdict, "security_verdict", verdict.classification)))

    sha256_val = html.escape(str(res.doc.hashes.get('sha256', 'N/A')))
    md5_val = html.escape(str(res.doc.hashes.get('md5', 'N/A')))
    sha1_val = html.escape(str(res.doc.hashes.get('sha1', 'N/A')))

    incomplete_alert = ""
    if res.analysis_status == "PARTIAL":
        incomplete_alert = """
        <div style="background: #854d0e; color: #fef08a; padding: 10px 14px; border-radius: 6px; margin-bottom: 12px; font-size: 0.9rem;">
            <strong>Warning: Analysis Incomplete</strong> — Some components could not be fully parsed or analyzed.
        </div>
        """

    overview_html = f"""
    <div style="background: #1e293b; padding: 20px; border-radius: 10px; border: 1px solid #334155; margin-bottom: 15px;">
        {incomplete_alert}
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h2 style="margin: 0; color: #f8fafc;">Sample: {safe_orig_name}</h2>
                <span style="color: #94a3b8; font-size: 0.9rem;">
                    Format: {safe_format} | Size: {res.doc.file_size_bytes} bytes | Entropy: {res.doc.file_entropy}
                </span>
                <div style="margin-top: 4px;">
                    <span style="background: #334155; color: #cbd5e1; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem;">Status: {safe_status}</span>
                    <span style="color: #94a3b8; font-size: 0.85rem; margin-left: 8px;">Verdict: <strong>{sec_verdict}</strong></span>
                </div>
            </div>
            <div style="text-align: right;">
                <span style="background: {b_color}; color: white; padding: 8px 16px; border-radius: 20px; font-weight: bold; font-size: 1.1rem;">
                    {safe_classification} (Score: {verdict.normalized_score}/100)
                </span>
            </div>
        </div>
        <p style="margin: 15px 0 0 0; color: #cbd5e1; font-size: 1rem;">{safe_explanation}</p>
        <div style="margin-top: 15px; font-family: monospace; font-size: 0.85rem; color: #38bdf8; background: #0f172a; padding: 10px; border-radius: 6px; word-break: break-all;">
            <strong>SHA-256:</strong> {sha256_val}<br>
            <strong>MD5:</strong> {md5_val} | <strong>SHA-1:</strong> {sha1_val}
        </div>
    </div>
    """

    # 2. Streams Table
    streams_data = [
        [s.name, s.storage_path, s.size_bytes, s.entropy, "Yes" if s.is_vba_related else "No", "High" if s.is_suspicious_entropy else "Normal"]
        for s in res.structure.streams
    ]

    # 3. Structural Anomalies
    anomalies_data = [[a] for a in res.structure.anomalies] if res.structure.anomalies else [["No structural anomalies detected."]]

    # 4. VBA Source Preview
    if res.vba.has_macros and res.vba.modules:
        vba_text = "\n\n".join([f"''' Module: {m.module_name} (Lines: {m.line_count}) '''\n{m.code}" for m in res.vba.modules])
    else:
        vba_text = "No VBA macros or code modules present in this document."

    # 5. Static Findings Table
    findings_data = [
        [f.severity, f.indicator_name, f.category, f"{f.source_module} (L{f.line_number or '-'})", f.evidence, f.explanation]
        for f in res.fused.deduplicated_findings
    ]

    # 6. Correlated Patterns Table
    patterns_data = [
        [p.severity, p.pattern_name, p.confidence, p.description, p.evidence_summary]
        for p in res.fused.correlated_patterns
    ]

    # 7. Deobfuscation Table
    deobf_data = [
        [d.transformation_type, d.original_expression, d.reconstructed_value, f"{d.source_module}:L{d.line_number}"]
        for d in res.deobf_results
    ]

    # 8. Extracted Payloads Table
    payloads_data = [
        [p.payload_id, p.extraction_method, p.payload_size, p.sha256[:16] + "...", p.entropy, p.supporting_evidence]
        for p in res.payloads
    ]

    # 9. Shellcode and API Hashes Table
    shellcode_summary = []
    if res.shellcode_report.is_likely_shellcode:
        for h in res.shellcode_report.detected_heuristics:
            shellcode_summary.append(["Heuristic", h, "-"])
        for r in res.shellcode_report.resolved_api_hashes:
            shellcode_summary.append(["API Hash", f"{r.module_name}!{r.api_name}", r.hash_value_hex])
    elif res.shellcode_report.detected_heuristics:
        for h in res.shellcode_report.detected_heuristics:
            shellcode_summary.append(["Note", h, "-"])
    else:
        shellcode_summary.append(["Status", "No shellcode characteristics detected", "-"])

    # 10. 18-Feature Vector Table
    f_dict = res.features.to_dict()
    features_data = [[k, str(v)] for k, v in f_dict.items()]

    # 11. YARA Rule text
    yara_text = res.yara_rule.rule_text

    return (
        overview_html,
        streams_data,
        anomalies_data,
        vba_text,
        findings_data,
        patterns_data,
        deobf_data,
        payloads_data,
        shellcode_summary,
        features_data,
        yara_text,
        str(res.html_report_path) if res.html_report_path else None,
        str(res.json_report_path) if res.json_report_path else None
    )


# Build the UI Layout
custom_theme = gr.themes.Soft(
    primary_hue="blue",
    neutral_hue="slate"
)

with gr.Blocks(title="Office Document Malware Triage Engine") as demo:
    gr.Markdown("""
    # Automated Triage Engine for Weaponized Office Documents
    ### Static Reverse Engineering, VBA Stomping, Deobfuscation, Shellcode & Risk Triage
    *Upload Microsoft Office documents (`.doc`, `.docm`, `.xls`, `.xlsm`) for instant safe static analysis.*
    """)

    with gr.Row():
        file_input = gr.File(label="Upload Document (.doc, .docm, .xls, .xlsm)", file_types=[".doc", ".docm", ".xls", ".xlsm"])

    analyze_btn = gr.Button("Analyze Document", variant="primary", size="lg")

    overview_output = gr.HTML()

    with gr.Tabs():
        with gr.Tab("Document Structure & Streams"):
            gr.Markdown("### OLE / OpenXML Stream Inventory & Shannon Entropy")
            streams_table = gr.Dataframe(
                headers=["Stream Name", "Storage Path", "Size (bytes)", "Entropy", "VBA Related", "Entropy Status"],
                label="Stream Structure",
                interactive=False
            )
            gr.Markdown("### Structural Anomalies")
            anomalies_table = gr.Dataframe(headers=["Anomaly Description"], label="Container Anomalies", interactive=False)

        with gr.Tab("VBA Source & Modules"):
            gr.Markdown("### Extracted VBA Macro Modules")
            vba_preview = gr.Code(label="Extracted Macro Code", lines=20)

        with gr.Tab("Static Findings & Attack Fusion"):
            gr.Markdown("### Deduplicated Evidence Findings")
            findings_table = gr.Dataframe(
                headers=["Severity", "Indicator", "Category", "Source Location", "Evidence Snippet", "Explanation"],
                label="Findings",
                interactive=False
            )
            gr.Markdown("### Correlated Attack Patterns (Multi-Stage Synergy)")
            patterns_table = gr.Dataframe(
                headers=["Severity", "Pattern Name", "Confidence", "Description", "Evidence Summary"],
                label="Attack Patterns",
                interactive=False
            )

        with gr.Tab("Deobfuscation & Payloads"):
            gr.Markdown("### AST-Reconstructed Obfuscated Strings")
            deobf_table = gr.Dataframe(
                headers=["Type", "Original Expression", "Reconstructed Value", "Source Line"],
                label="Deobfuscated Strings",
                interactive=False
            )
            gr.Markdown("### Extracted Embedded Payloads & Byte Arrays")
            payloads_table = gr.Dataframe(
                headers=["Payload ID", "Method", "Size (bytes)", "SHA-256", "Entropy", "Source Evidence"],
                label="Extracted Payloads",
                interactive=False
            )

        with gr.Tab("Shellcode & API Hashes"):
            gr.Markdown("### Capstone Static Disassembly & ROR13 API Resolution")
            shellcode_table = gr.Dataframe(
                headers=["Category", "Detail", "Hex / Offset"],
                label="Shellcode Findings",
                interactive=False
            )

        with gr.Tab("18-Feature Vector"):
            gr.Markdown("### Standardized 18-Dimensional Feature Vector [f1..f18]")
            features_table = gr.Dataframe(
                headers=["Feature Name", "Value"],
                label="18 Features",
                interactive=False
            )

        with gr.Tab("YARA Rule & Export"):
            gr.Markdown("### Synthesized YARA Detection Rule")
            yara_output = gr.Code(label="YARA Rule Text", lines=15)
            with gr.Row():
                download_html = gr.File(label="Download Analyst HTML Report")
                download_json = gr.File(label="Download Machine-Readable JSON")

    analyze_btn.click(
        fn=analyze_document,
        inputs=[file_input],
        outputs=[
            overview_output,
            streams_table,
            anomalies_table,
            vba_preview,
            findings_table,
            patterns_table,
            deobf_table,
            payloads_table,
            shellcode_table,
            features_table,
            yara_output,
            download_html,
            download_json
        ]
    )


if __name__ == "__main__":
    demo.launch(server_name="127.0.0.1", server_port=7860, show_error=True, theme=custom_theme)

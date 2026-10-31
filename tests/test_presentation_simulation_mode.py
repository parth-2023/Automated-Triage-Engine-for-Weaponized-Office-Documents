"""
Test Suite for Presentation Simulation Mode.

Verifies:
1. Exact SHA-256 hash matching activates simulation mode.
2. A different file with the same filename does NOT activate simulation.
3. A different file with the same extension does NOT activate simulation.
4. Actual file metadata (hashes, size, format, entropy) is accurately preserved.
5. Simulated findings are consistent across all dashboard outputs and tabs.
6. HTML and JSON exports identify simulation mode, target hash, and recommendation.
7. Normal analysis workflow remains completely unchanged for nonmatching files.
"""

import json
import pytest
from pathlib import Path

from core.pipeline import TriagePipeline, TriagePipelineResult
from core.presentation_mode import (
    TARGET_SIMULATION_SHA256,
    TARGET_SIMULATION_FILENAME,
    SIMULATION_VERDICT,
    SIMULATION_RISK_LEVEL,
    SIMULATION_RISK_SCORE,
    SIMULATION_RECOMMENDATION,
    is_presentation_simulation_target,
)
from app import analyze_document
from samples.fixture_generator import generate_all_fixtures


@pytest.fixture(scope="session")
def fixtures():
    return generate_all_fixtures()


class TestPresentationSimulationMode:
    def test_target_hash_identification(self):
        """Verify hash matching logic is exact, case-insensitive, and does not match arbitrary hashes."""
        assert is_presentation_simulation_target(TARGET_SIMULATION_SHA256) is True
        assert is_presentation_simulation_target(TARGET_SIMULATION_SHA256.upper()) is True
        assert is_presentation_simulation_target({"sha256": TARGET_SIMULATION_SHA256}) is True
        assert is_presentation_simulation_target("0" * 64) is False
        assert is_presentation_simulation_target(None) is False
        assert is_presentation_simulation_target("") is False

    def test_exact_hash_activates_simulation(self, fixtures):
        """Uploading the exact target file activates Presentation Simulation Mode."""
        target_path = fixtures.get("presentation_simulation_docm")
        if not target_path or not Path(target_path).exists():
            pytest.skip("Target presentation simulation file not present in test fixtures.")

        pipeline = TriagePipeline()
        res = pipeline.analyze_file(str(target_path))

        assert res.is_simulation is True
        assert res.verdict.security_verdict == SIMULATION_VERDICT
        assert res.verdict.classification == SIMULATION_RISK_LEVEL
        assert res.verdict.normalized_score == SIMULATION_RISK_SCORE
        assert res.recommendation == SIMULATION_RECOMMENDATION
        assert "PRESENTATION SIMULATION" in res.verdict.explanation

    def test_same_filename_different_hash_does_not_activate_simulation(self, fixtures):
        """A file named Invoice_September_2026.docm with a different hash MUST NOT activate simulation."""
        diff_path = fixtures.get("same_filename_different_hash")
        assert diff_path is not None and Path(diff_path).exists()
        assert Path(diff_path).name == TARGET_SIMULATION_FILENAME

        pipeline = TriagePipeline()
        res = pipeline.analyze_file(str(diff_path))

        # Must run normal analysis pipeline, not simulation
        assert getattr(res, "is_simulation", False) is False
        assert res.verdict.normalized_score != SIMULATION_RISK_SCORE

    def test_same_extension_different_file_does_not_activate_simulation(self, fixtures):
        """Other .docm files (e.g. harmless macro docm) must execute the normal analysis pipeline."""
        macro_docm = fixtures["docm_harmless_vba"]
        pipeline = TriagePipeline()
        res = pipeline.analyze_file(str(macro_docm))

        assert getattr(res, "is_simulation", False) is False

    def test_actual_metadata_preserved_in_simulation(self, fixtures):
        """Actual metadata (size, hashes, format, entropy) must be measured from the file itself."""
        target_path = fixtures.get("presentation_simulation_docm")
        if not target_path or not Path(target_path).exists():
            pytest.skip("Target presentation simulation file not present.")

        pipeline = TriagePipeline()
        res = pipeline.analyze_file(str(target_path))

        # Check hashes
        assert res.doc.hashes["sha256"].lower() == TARGET_SIMULATION_SHA256.lower()
        assert len(res.doc.hashes["md5"]) == 32
        assert len(res.doc.hashes["sha1"]) == 40
        # Check actual file size matches disk size
        assert res.doc.file_size_bytes == Path(target_path).stat().st_size
        # Check entropy is a realistic float > 0
        assert res.doc.file_entropy > 0.0
        # Check format is detected
        assert res.doc.detected_format == "OpenXML"

    def test_simulated_findings_consistency_across_all_tabs(self, fixtures):
        """Verify illustrative findings agree across all tabs and data structures."""
        target_path = fixtures.get("presentation_simulation_docm")
        if not target_path or not Path(target_path).exists():
            pytest.skip("Target presentation simulation file not present.")

        pipeline = TriagePipeline()
        res = pipeline.analyze_file(str(target_path))

        # 1. Structure & Streams
        assert len(res.structure.streams) >= 5
        assert any("[SIMULATION]" in a for a in res.structure.anomalies)

        # 2. VBA Source & Modules
        assert res.vba.has_macros is True
        assert len(res.vba.modules) == 1
        assert "VirtualAlloc" in res.vba.modules[0].code
        assert "AutoOpen" in res.vba.modules[0].code

        # 3. Static Findings & Attack Patterns
        finding_names = [f.indicator_name for f in res.fused.deduplicated_findings]
        assert "AutoOpen_Trigger" in finding_names
        assert "Win32API_VirtualAlloc" in finding_names
        assert "Win32API_WriteProcessMemory" in finding_names
        assert "Win32API_CreateThread" in finding_names
        assert "Chr_Obfuscation" in finding_names
        assert "Network_C2_Indicator" in finding_names

        pattern_names = [p.pattern_name for p in res.fused.correlated_patterns]
        assert "Staged Memory Injection Loader" in pattern_names
        assert "Automated C2 Stager" in pattern_names

        # 4. Deobfuscation & Payloads
        assert len(res.deobf_results) >= 1
        assert any("c2-finance-update.org" in d.reconstructed_value for d in res.deobf_results)
        assert len(res.payloads) == 1
        assert res.payloads[0].payload_size == 1024

        # 5. Shellcode & Hashes
        assert res.shellcode_report.is_likely_shellcode is True
        assert len(res.shellcode_report.resolved_api_hashes) == 3
        resolved_names = [r.api_name for r in res.shellcode_report.resolved_api_hashes]
        assert "VirtualAlloc" in resolved_names
        assert "LoadLibraryA" in resolved_names
        assert "GetProcAddress" in resolved_names

        # 6. 18-Feature Vector
        f_dict = res.features.to_dict()
        assert len(f_dict) == 18
        assert f_dict["f1_file_size_bytes"] == res.doc.file_size_bytes
        assert f_dict["f3_has_vba_project"] == 1
        assert f_dict["f4_stomping_discrepancy"] == 0.75
        assert f_dict["f13_has_memory_alloc_api"] == 1
        assert f_dict["f14_has_memory_copy_api"] == 1
        assert f_dict["f15_has_thread_create_api"] == 1
        assert f_dict["f18_has_c2_network_indicator"] == 1

        # 7. YARA Rule
        assert "presentation_simulation_invoice_indicator" in res.yara_rule.rule_text
        assert "VirtualAlloc" in res.yara_rule.rule_text
        assert res.yara_rule.is_valid_syntax is True

    def test_dashboard_callback_simulation_integration(self, fixtures):
        """Test Gradio analyze_document callback returns 13 outputs with presentation simulation indicators."""
        target_path = fixtures.get("presentation_simulation_docm")
        if not target_path or not Path(target_path).exists():
            pytest.skip("Target presentation simulation file not present.")

        outputs = analyze_document(str(target_path))
        assert len(outputs) == 13

        overview_html = outputs[0]
        assert "PRESENTATION SIMULATION" in overview_html
        assert "IMMEDIATE ANALYST REVIEW" in overview_html
        assert "CRITICAL (Score: 85/100)" in overview_html
        assert "SUSPICIOUS" in overview_html

        vba_preview = outputs[3]
        assert "PRESENTATION SIMULATION MODE" in vba_preview
        assert "Sub AutoOpen()" in vba_preview

        findings_data = outputs[4]
        assert len(findings_data) >= 5

        # Check export paths
        html_export = outputs[11]
        json_export = outputs[12]
        assert html_export is not None and Path(html_export).exists()
        assert json_export is not None and Path(json_export).exists()

    def test_exports_identify_simulation_mode(self, fixtures):
        """HTML and JSON exports must explicitly state simulation mode, target hash, and recommendation."""
        target_path = fixtures.get("presentation_simulation_docm")
        if not target_path or not Path(target_path).exists():
            pytest.skip("Target presentation simulation file not present.")

        pipeline = TriagePipeline()
        res = pipeline.analyze_file(str(target_path))

        # Check JSON export
        assert res.json_report_path is not None and Path(res.json_report_path).exists()
        with open(res.json_report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data.get("simulation_mode") is True
        assert data.get("target_file_hash") == TARGET_SIMULATION_SHA256
        assert data.get("recommendation") == SIMULATION_RECOMMENDATION
        assert data["analysis_overview"]["security_verdict"] == SIMULATION_VERDICT
        assert data["analysis_overview"]["risk_classification"] == SIMULATION_RISK_LEVEL
        assert data["analysis_overview"]["normalized_score"] == SIMULATION_RISK_SCORE
        assert data["sample_identity"]["hashes"]["sha256"].lower() == TARGET_SIMULATION_SHA256.lower()

        # Check HTML export
        assert res.html_report_path is not None and Path(res.html_report_path).exists()
        html_text = Path(res.html_report_path).read_text(encoding="utf-8")
        assert "PRESENTATION SIMULATION MODE" in html_text
        assert TARGET_SIMULATION_SHA256 in html_text
        assert "IMMEDIATE ANALYST REVIEW" in html_text
        assert "CRITICAL" in html_text

    def test_normal_analysis_remains_unchanged(self, fixtures):
        """Normal non-matching files undergo standard static analysis without any simulation markers."""
        clean_doc = fixtures["valid_doc"]
        pipeline = TriagePipeline()
        res = pipeline.analyze_file(str(clean_doc))

        assert getattr(res, "is_simulation", False) is False
        assert res.verdict.classification == "LOW"
        assert res.verdict.normalized_score == 0
        assert "PRESENTATION SIMULATION" not in res.verdict.explanation
        assert "PRESENTATION SIMULATION" not in res.report_data.get("explanation", "")


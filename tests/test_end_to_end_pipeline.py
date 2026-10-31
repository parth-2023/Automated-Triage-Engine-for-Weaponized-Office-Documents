"""
End-to-End Integration Tests for the Automated Triage Engine.

Exercises the full 15-step pipeline and the Gradio UI callback
across clean, suspicious, corrupt, and unsupported inputs.
"""

import os
import pytest
from pathlib import Path

from core.pipeline import TriagePipeline, TriagePipelineResult
from app import analyze_document
from samples.fixture_generator import generate_all_fixtures


@pytest.fixture(scope="session")
def fixtures():
    return generate_all_fixtures()


class TestEndToEndPipeline:
    def test_benign_document_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["valid_doc"]
        res = pipeline.analyze_file(str(path))

        assert res.doc.is_valid is True
        assert res.structure.is_corrupt is False
        assert res.verdict.classification == "LOW"
        assert res.features is not None
        assert len(res.features.to_dict()) == 18
        assert res.html_report_path is not None
        assert Path(res.html_report_path).exists()
        assert res.json_report_path is not None
        assert Path(res.json_report_path).exists()

    def test_macro_document_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["docm_harmless_vba"]
        res = pipeline.analyze_file(str(path))

        assert res.doc.is_valid is True
        assert res.vba.has_macros is True
        assert len(res.vba.modules) >= 1
        assert res.features is not None
        assert len(res.features.to_numeric_list()) == 18
        assert res.yara_rule is not None
        assert Path(res.html_report_path).exists()
        assert Path(res.json_report_path).exists()

    def test_corrupt_document_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["corrupt_doc"]
        res = pipeline.analyze_file(str(path))

        assert res.structure.is_corrupt is True
        assert res.verdict.classification == "INCONCLUSIVE"
        assert res.html_report_path is not None
        assert Path(res.html_report_path).exists()
        assert res.json_report_path is not None
        assert Path(res.json_report_path).exists()

    def test_unsupported_document_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["unsupported_file"]
        res = pipeline.analyze_file(str(path))

        assert res.doc.is_valid is False
        assert res.verdict.classification in ["UNSUPPORTED", "UNSUPPORTED FORMAT"]
        assert res.html_report_path is not None
        assert Path(res.html_report_path).exists()
        assert res.json_report_path is not None
        assert Path(res.json_report_path).exists()

    def test_stage_failure_prevents_completed_status(self, fixtures, monkeypatch):
        # Simulate payload extraction or stomping failure
        from core.payload_extractor import PayloadExtractor
        def raise_extraction_error(*args, **kwargs):
            raise RuntimeError("Simulated payload extraction library failure")
        monkeypatch.setattr(PayloadExtractor, "extract_all", raise_extraction_error)

        pipeline = TriagePipeline()
        path = fixtures["docm_harmless_vba"]
        res = pipeline.analyze_file(str(path))

        # Overall analysis status MUST NOT be COMPLETED
        assert res.analysis_status == "PARTIAL"
        assert res.stage_statuses["payload_extraction"] == "FAILED"
        assert "f16_extracted_payload_bytes" in res.features.failed_features
        # Low findings on partial analysis must be marked PARTIAL
        assert res.verdict.classification == "PARTIAL"
        assert "INCOMPLETE ANALYSIS" in res.verdict.security_verdict

    def test_docx_clean_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["valid_docx"]
        res = pipeline.analyze_file(str(path))

        assert res.doc.is_valid is True
        assert res.doc.package_type == "Word"
        assert res.structure.package_type == "Word"
        assert res.vba.has_macros is False
        assert res.verdict.classification == "LOW"
        assert res.analysis_status == "COMPLETED"
        # Macro-specific features should be NOT_APPLICABLE, not FAILED
        assert "f4_stomping_discrepancy" in res.features.not_applicable_features
        assert "f6_pcode_token_count" in res.features.not_applicable_features

    def test_xlsx_clean_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["valid_xlsx"]
        res = pipeline.analyze_file(str(path))

        assert res.doc.is_valid is True
        assert res.doc.package_type == "Excel"
        assert res.verdict.classification == "LOW"
        assert res.analysis_status == "COMPLETED"

    def test_pptx_clean_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["valid_pptx"]
        res = pipeline.analyze_file(str(path))

        assert res.doc.is_valid is True
        assert res.doc.package_type == "PowerPoint"
        assert res.verdict.classification == "LOW"
        assert res.analysis_status == "COMPLETED"

    def test_remote_template_injection_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["docx_remote_template"]
        res = pipeline.analyze_file(str(path))

        assert res.doc.is_valid is True
        assert any(f.indicator_name == "RemoteTemplateInjection" for f in res.fused.deduplicated_findings)
        assert res.verdict.normalized_score > 20
        assert res.verdict.classification in ["HIGH", "MEDIUM"]

    def test_embedded_ole_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["docx_embedded_ole"]
        res = pipeline.analyze_file(str(path))

        assert res.doc.is_valid is True
        assert any(f.indicator_name == "EmbeddedOleObject" for f in res.fused.deduplicated_findings)

    def test_mismatched_extension_pipeline(self, fixtures):
        pipeline = TriagePipeline()
        path = fixtures["docx_mismatched_ole"]
        res = pipeline.analyze_file(str(path))

        assert any(f.indicator_name == "ExtensionMismatch" for f in res.fused.deduplicated_findings)


class TestDashboardCallbackAndSecurity:
    def test_analyze_document_none_input(self):
        outputs = analyze_document(None)
        assert len(outputs) == 13
        assert "Please upload a valid Office document" in outputs[0]

    def test_analyze_document_benign(self, fixtures):
        path = str(fixtures["valid_doc"])
        outputs = analyze_document(path)
        assert len(outputs) == 13
        overview_html = outputs[0]
        assert ("LOW" in overview_html) or ("PARTIAL" in overview_html)
        features_data = outputs[9]
        assert len(features_data) == 18
        # Reports
        assert outputs[11] is not None and Path(outputs[11]).exists()
        assert outputs[12] is not None and Path(outputs[12]).exists()

    def test_analyze_document_unsupported_format(self, fixtures):
        path = str(fixtures["unsupported_file"])
        outputs = analyze_document(path)
        assert len(outputs) == 13
        assert "Unsupported File Format" in outputs[0]

    def test_html_injection_prevention(self, fixtures):
        # Call pipeline with an untrusted malicious filename containing HTML tags
        pipeline = TriagePipeline()
        evil_name = 'sample_<script>alert(1)</script>.docm'
        valid_path = fixtures["valid_doc"]
        res = pipeline.analyze_file(str(valid_path), filename=evil_name)

        assert res.html_report_path is not None
        html_out = Path(res.html_report_path).read_text(encoding="utf-8")

        # Verify that raw script tags are strictly absent and properly HTML escaped
        assert "<script>alert(1)</script>" not in html_out
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out

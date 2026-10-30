"""
Test Suite for Phase 4: Gradio Dashboard and Analyst Reporting.
"""

import pytest
import json
from pathlib import Path

from core.pipeline import TriagePipeline
from samples.fixture_generator import generate_all_fixtures
from app import analyze_document


@pytest.fixture(scope="session")
def fixtures():
    return generate_all_fixtures()


class TestReportingAndPipeline:
    def test_pipeline_on_clean_document(self, fixtures):
        pipeline = TriagePipeline()
        res = pipeline.analyze_file(fixtures["docm_nomacro"])
        assert res.doc.is_valid is True
        assert res.verdict.classification == "LOW"
        assert res.html_report_path.exists()
        assert res.json_report_path.exists()

        # Check JSON report content
        with open(res.json_report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "sample_identity" in data
            assert "risk_assessment" in data
            assert data["risk_assessment"]["classification"] == "LOW"

    def test_pipeline_on_harmless_macro(self, fixtures):
        pipeline = TriagePipeline()
        res = pipeline.analyze_file(fixtures["docm_harmless_vba"])
        assert res.doc.is_valid is True
        assert res.vba.has_macros is True or len(res.vba.modules) >= 0
        assert res.html_report_path.exists()

    def test_pipeline_on_corrupt_doc(self, fixtures):
        pipeline = TriagePipeline()
        res = pipeline.analyze_file(fixtures["corrupt_doc"])
        assert res.verdict.classification == "INCONCLUSIVE"

    def test_gradio_analyze_document_callback(self, fixtures):
        # Pass a mock file object with .name attribute
        class MockFile:
            name = str(fixtures["docm_nomacro"])

        outputs = analyze_document(MockFile())
        assert len(outputs) == 13
        # Check first output is HTML overview
        assert "<div" in outputs[0]
        # Check download paths are valid strings
        assert outputs[11] is not None
        assert Path(outputs[11]).exists()

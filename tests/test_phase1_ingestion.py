"""
Test Suite for Phase 1: File Ingestion, Document Inspection, and VBA Extraction.
Runs against harmless synthetic fixtures.
"""

import pytest
from pathlib import Path

from core.ingestion import IngestionManager, sanitize_filename
from core.hashing import calculate_hashes, shannon_entropy
from core.metadata import MetadataExtractor
from core.document_inspector import DocumentInspector
from core.vba_extractor import VBAExtractor
from samples.fixture_generator import generate_all_fixtures, SAMPLE_DIR


@pytest.fixture(scope="session")
def fixtures():
    return generate_all_fixtures()


class TestHashingAndEntropy:
    def test_shannon_entropy_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_shannon_entropy_uniform(self):
        # All same byte -> 0.0
        assert shannon_entropy(b"AAAAAA") == 0.0

    def test_shannon_entropy_high(self):
        # 256 all unique bytes -> 8.0 bits
        full_byte_range = bytes(range(256))
        ent = shannon_entropy(full_byte_range)
        assert ent == 8.0

    def test_hashes(self, fixtures):
        h = calculate_hashes(fixtures["valid_doc"])
        assert len(h["sha256"]) == 64
        assert len(h["md5"]) == 32
        assert len(h["sha1"]) == 40


class TestIngestionManager:
    def test_sanitize_filename(self):
        assert sanitize_filename("../../etc/passwd") == "passwd"
        assert sanitize_filename("..\\..\\windows\\system32\\calc.exe") == "calc.exe"
        assert sanitize_filename("Normal_Doc.docm") == "Normal_Doc.docm"

    def test_ingest_valid_ole(self, fixtures):
        with IngestionManager() as mgr:
            doc = mgr.ingest_file(fixtures["valid_doc"])
            assert doc.is_valid is True
            assert doc.detected_format == "OLE"
            assert doc.file_size_bytes > 0
            assert len(doc.hashes["sha256"]) == 64

    def test_ingest_valid_openxml(self, fixtures):
        with IngestionManager() as mgr:
            doc = mgr.ingest_file(fixtures["docm_nomacro"])
            assert doc.is_valid is True
            assert doc.detected_format == "OpenXML"
            assert doc.file_size_bytes > 0

    def test_ingest_empty_file(self, fixtures):
        with IngestionManager() as mgr:
            doc = mgr.ingest_file(fixtures["empty_file"])
            assert doc.is_valid is False
            assert doc.detected_format == "EMPTY"
            assert "empty" in doc.error_message.lower()

    def test_ingest_unsupported_file(self, fixtures):
        with IngestionManager() as mgr:
            doc = mgr.ingest_file(fixtures["unsupported_file"])
            assert doc.is_valid is False
            assert doc.detected_format == "UNSUPPORTED"
            assert "unsupported" in doc.error_message.lower()

    def test_ingest_oversized_file(self, fixtures):
        # Set artificially small max_file_size to test boundary
        with IngestionManager(max_file_size=100) as mgr:
            doc = mgr.ingest_file(fixtures["valid_doc"])
            assert doc.is_valid is False
            assert doc.detected_format == "OVERSIZED"


class TestDocumentInspection:
    def test_inspect_ole(self, fixtures):
        res = DocumentInspector.inspect(fixtures["valid_doc"], "OLE")
        assert res.is_corrupt is False
        assert res.stream_count >= 1
        assert res.streams[0].name != ""

    def test_inspect_openxml_clean(self, fixtures):
        res = DocumentInspector.inspect(fixtures["docm_nomacro"], "OpenXML")
        assert res.is_corrupt is False
        assert res.stream_count >= 3
        assert res.has_vba_project is False

    def test_inspect_openxml_with_vba(self, fixtures):
        res = DocumentInspector.inspect(fixtures["docm_harmless_vba"], "OpenXML")
        assert res.is_corrupt is False
        assert res.has_vba_project is True
        assert "vbaProject.bin" in res.vba_project_location

    def test_inspect_corrupt_ole(self, fixtures):
        res = DocumentInspector.inspect(fixtures["corrupt_doc"], "OLE")
        assert res.is_corrupt is True

    def test_inspect_malformed_zip(self, fixtures):
        res = DocumentInspector.inspect(fixtures["malformed_zip"], "OpenXML")
        assert res.is_corrupt is True

    def test_inspect_zip_slip_detection(self, fixtures):
        res = DocumentInspector.inspect(fixtures["zip_slip"], "OpenXML")
        assert any("Zip slip" in anomaly for anomaly in res.anomalies)


class TestMetadataExtraction:
    def test_openxml_metadata(self, fixtures):
        meta = MetadataExtractor.extract(fixtures["docm_nomacro"], "OpenXML")
        assert meta["title"] == "Benign Test Document"
        assert meta["author"] == "Security Analyst"
        assert meta["creating_application"] == "Microsoft Office Word"


class TestVBAExtractor:
    def test_extract_clean_document(self, fixtures):
        res = VBAExtractor.extract_vba(fixtures["docm_nomacro"])
        assert res.has_macros is False
        assert res.module_count == 0

    def test_extract_harmless_vba(self, fixtures):
        res = VBAExtractor.extract_vba(fixtures["docm_harmless_vba"])
        assert res.has_macros is True
        assert res.module_count >= 1
        assert len(res.modules) >= 1
        assert any("Document_Open" in p for p in res.modules[0].procedures)

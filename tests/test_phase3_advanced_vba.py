"""
Test Suite for Phase 3: Advanced VBA Analysis, Stomping, and Payload Extraction.
"""

import pytest
from pathlib import Path

from core.deobfuscator import RestrictedVbaDeobfuscator
from core.payload_extractor import PayloadExtractor
from core.stomping_detector import StompingDetector
from core.vba_extractor import VBAModule, VBAExtractionResult
from samples.fixture_generator import generate_all_fixtures


@pytest.fixture(scope="session")
def fixtures():
    return generate_all_fixtures()


class TestDeobfuscator:
    def test_chr_reconstruction(self):
        line = 'cmd = Chr(99) & Chr(97) & Chr(108) & Chr(99)'
        res = RestrictedVbaDeobfuscator.deobfuscate_chr_chains(line, "Mod1", 1)
        assert len(res) == 1
        assert res[0].reconstructed_value == "calc"
        assert res[0].transformation_type == "CHR_CONCAT"

    def test_chr_with_simple_math(self):
        line = 'x = Chr(60 + 5) & Chr(70 - 4)'
        res = RestrictedVbaDeobfuscator.deobfuscate_chr_chains(line, "Mod1", 1)
        assert len(res) == 1
        assert res[0].reconstructed_value == "AB"

    def test_strreverse(self):
        line = 'tool = StrReverse("exe.llehsrewop")'
        res = RestrictedVbaDeobfuscator.deobfuscate_strreverse(line, "Mod1", 1)
        assert len(res) == 1
        assert res[0].reconstructed_value == "powershell.exe"

    def test_string_concatenation(self):
        line = 'url = "http://" & "example." & "com/payload"'
        res = RestrictedVbaDeobfuscator.deobfuscate_concatenations(line, "Mod1", 1)
        assert len(res) >= 1
        assert any("http://example.com/payload" in r.reconstructed_value for r in res)

    def test_base64_decode(self):
        line = 'b = "SGVsbG8gV29ybGQgZnJvbSBWYmE="'
        res = RestrictedVbaDeobfuscator.deobfuscate_base64_and_hex(line, "Mod1", 1)
        assert len(res) >= 1
        assert any("Hello World" in r.reconstructed_value for r in res)

    def test_xor_stream(self):
        raw = b"SecretData"
        key = 0x5A
        encrypted = bytes([b ^ key for b in raw])
        decrypted = RestrictedVbaDeobfuscator.evaluate_xor_stream(encrypted, key)
        assert decrypted == raw


class TestPayloadExtractor:
    def test_extract_byte_array(self):
        code = 'Dim buf\nbuf = Array(77, 90, 144, 0, 3, 0, 0, 0, 4, 0, 0, 0, 255, 255, 0, 0)'
        payloads = PayloadExtractor.extract_from_code(code, "ModShell", "sample.docm")
        assert len(payloads) == 1
        p = payloads[0]
        assert p.payload_size == 16
        assert p.raw_bytes[:2] == b"MZ"
        assert len(p.sha256) == 64
        assert p.extraction_method == "VBA_BYTE_ARRAY"

    def test_extract_hex_buffer(self):
        code = 'Dim h\nh = "4D5A90000300000004000000FFFF0000B800000000000000"'
        payloads = PayloadExtractor.extract_from_code(code, "ModHex", "sample.docm")
        assert len(payloads) == 1
        p = payloads[0]
        assert p.payload_size == 24
        assert p.raw_bytes[:2] == b"MZ"
        assert p.extraction_method == "HEX_BUFFER"


class TestStompingDetector:
    def test_stomping_clean_document(self, fixtures):
        clean_vba = VBAExtractionResult(False, 0, 0, [])
        res = StompingDetector.analyze(fixtures["docm_nomacro"], clean_vba)
        assert res.is_stomped is False
        assert res.sdi_score == 0.0

    def test_stomping_harmless_macro(self, fixtures):
        vba = VBAExtractionResult(True, 1, 3, [
            VBAModule("Mod1", "VBA/Mod1", "Mod1", "Sub Document_Open()\nMsgBox \"Hello\"\nEnd Sub", 3, [])
        ])
        res = StompingDetector.analyze(fixtures["docm_harmless_vba"], vba)
        assert res.analysis_status in ["COMPLETED", "PARTIAL"]
        assert 0.0 <= res.sdi_score <= 1.0

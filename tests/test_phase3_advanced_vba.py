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

    def test_variable_assignment_propagation(self):
        code = (
            'cmd1 = Chr(99) & Chr(97) & Chr(108) & Chr(99)\n'
            'cmd2 = cmd1 & ".exe"\n'
        )
        results = RestrictedVbaDeobfuscator.analyze_module(code, "Mod1")
        reconstructed = [r.reconstructed_value for r in results]
        assert any("calc" in r for r in reconstructed)
        assert any("calc.exe" in r for r in reconstructed)

    def test_string_aware_variable_substitution(self):
        # 1. Variable name inside ordinary string literal must NOT be replaced
        var_table = {"var1": "MALICIOUS", "target": "PAYLOAD"}
        text_with_literal = 'msg = "This is var1 inside literal" & var1'
        substituted = RestrictedVbaDeobfuscator._substitute_vars(text_with_literal, var_table)
        assert substituted == 'msg = "This is var1 inside literal" & "MALICIOUS"'

        # 2. Variable name inside escaped quotes ("") must NOT be replaced
        escaped_literal = 'banner = "Prefix ""var1"" and ""target"" text" & target'
        sub_escaped = RestrictedVbaDeobfuscator._substitute_vars(escaped_literal, var_table)
        assert sub_escaped == 'banner = "Prefix ""var1"" and ""target"" text" & "PAYLOAD"'

        # 3. Concatenation of multiple variables and string literals
        multi_concat = 'url = target & "/download?id=" & var1'
        sub_concat = RestrictedVbaDeobfuscator._substitute_vars(multi_concat, var_table)
        assert sub_concat == 'url = "PAYLOAD" & "/download?id=" & "MALICIOUS"'

        # 4. Verify end-to-end reconstruction in analyze_module
        full_code = (
            'part1 = "powershell"\n'
            'msg = "Do not replace part1 in here: " & part1\n'
        )
        results = RestrictedVbaDeobfuscator.analyze_module(full_code, "ModStringAware")
        reconstructed = [r.reconstructed_value for r in results]
        # Must contain reconstructed concatenation with literal preserved
        assert any("Do not replace part1 in here: powershell" in r for r in reconstructed)

    def test_bounded_xor_loop_evaluation(self):
        # Statically assign a buffer and an XOR loop
        # "calc.exe" XOR 22 (0x16) = [117, 119, 122, 117, 56, 115, 110, 115]
        code = (
            'Dim buf\n'
            'buf = Array(117, 119, 122, 117, 56, 115, 110, 115)\n'
            'For i = 0 To 7\n'
            '    buf(i) = buf(i) Xor 22\n'
            'Next i\n'
        )
        results = RestrictedVbaDeobfuscator.analyze_module(code, "ModXor")
        xor_results = [r for r in results if r.transformation_type == "XOR_DECRYPT"]
        assert len(xor_results) >= 1
        assert any(r.is_complete and "calc.exe" in r.reconstructed_value for r in xor_results)


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

    def test_extract_from_deobfuscated_results(self):
        from core.deobfuscator import DeobfuscationResult
        raw_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 32
        deobf_results = [
            DeobfuscationResult(
                original_expression="b64_str",
                reconstructed_value="<binary>",
                transformation_type="BASE64_DECODE",
                source_module="ModPayload",
                line_number=10,
                confidence="High",
                is_complete=True,
                raw_bytes=raw_pe
            )
        ]
        payloads = PayloadExtractor.extract_from_deobf(deobf_results, "sample.docm")
        assert len(payloads) == 1
        p = payloads[0]
        assert p.payload_size == len(raw_pe)
        assert p.raw_bytes[:2] == b"MZ"
        assert p.extraction_method == "DEOBF_BASE64_DECODE"
        assert p.confidence == "High"


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

    def test_stomping_discrepancy_evaluation(self):
        # VBA source declares only benign MsgBox
        source_code = 'Sub Document_Open()\nMsgBox "Hello Benign"\nEnd Sub'
        source_data = StompingDetector._extract_source_constructs(source_code)

        # Simulated P-code data containing high-risk invocation absent from source
        pcode_data = {
            "token_count": 50,
            "procedures": ["Document_Open"],
            "calls": ["Shell", "VirtualAlloc"],
            "strings": ["Hello Benign"],
        }
        discrepancies = StompingDetector.compare_pcode_to_source(pcode_data, source_data, "ModStomped")
        assert len(discrepancies) >= 2
        assert any(d.pcode_token == "Shell" for d in discrepancies)
        assert any(d.severity == "CRITICAL" for d in discrepancies)

        result = StompingDetector.evaluate_discrepancies(discrepancies, pcode_token_count=50, source_line_count=3)
        assert result.is_stomped is True
        assert result.sdi_score >= 0.8
        assert result.confidence == "High"

    def test_stomping_single_high_risk_call_alone_not_stomped(self):
        # Single isolated call mismatch must NOT unilaterally cause stomped verdict
        source_code = 'Sub Main()\nDim x As Integer\nEnd Sub'
        source_data = StompingDetector._extract_source_constructs(source_code)
        pcode_data = {
            "token_count": 10,
            "procedures": ["Main"],
            "calls": ["Shell"],
            "strings": [],
        }
        discrepancies = StompingDetector.compare_pcode_to_source(pcode_data, source_data, "ModSingle")
        assert len(discrepancies) == 1
        result = StompingDetector.evaluate_discrepancies(discrepancies, pcode_token_count=10, source_line_count=3)
        # Should NOT classify as stomped solely based on a single high-risk API
        assert result.is_stomped is False

    def test_stomping_benign_intermodule_call(self):
        # Call in Mod1 is defined in Mod2 source; cross-module check must prevent false positive
        source_mod1 = StompingDetector._extract_source_constructs('Sub Foo()\nEnd Sub')
        source_mod2 = StompingDetector._extract_source_constructs('Sub Helper()\nHelperFunc\nEnd Sub')
        all_words = source_mod1["words"] | source_mod2["words"]

        pcode_mod1 = {
            "token_count": 20,
            "procedures": ["Foo"],
            "calls": ["HelperFunc"],  # Defined in mod2
            "strings": [],
        }
        discrepancies = StompingDetector.compare_pcode_to_source(
            pcode_mod1, source_mod1, "Mod1", all_source_words=all_words
        )
        assert len(discrepancies) == 0

    def test_stomping_module_splitting_and_missing_modules(self):
        pcode_text = (
            "Module streams:\n"
            "VBA/Module1 - 500 bytes\n"
            "ProcDef: Sub Alpha\n"
            "VBA/ModuleHidden - 800 bytes\n"
            "ProcDef: Sub SecretPayload\n"
        )
        split_map = StompingDetector._split_pcode_by_modules(pcode_text)
        assert "module1" in split_map
        assert "modulehidden" in split_map

    def test_stomping_failure_handling(self, fixtures, monkeypatch):
        # Simulated extraction failure must produce FAILED status
        def raise_pcode_err(*args, **kwargs):
            raise RuntimeError("Corrupt PCode stream version unsupported")
        import pcodedmp.pcodedmp as pcode_engine
        monkeypatch.setattr(pcode_engine, "processFile", raise_pcode_err)

        vba = VBAExtractionResult(True, 1, 5, [
            VBAModule("Mod1", "VBA/Mod1", "Mod1", "Sub Test()\nEnd Sub", 2, [])
        ])
        res = StompingDetector.analyze(fixtures["docm_harmless_vba"], vba)
        assert res.analysis_status == "FAILED"
        assert res.is_stomped is False
        assert len(res.limitations) > 0
        assert "Corrupt PCode" in res.notes[0]

"""
Test Suite for Phase 6: YARA Rule Synthesis, Validation, and Scoping.
"""

import pytest
from pathlib import Path
from unittest.mock import patch

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from core.ingestion import IngestedDocument
from core.fusion import DetectionFusionEngine
from core.static_analyzer import Finding
from core.deobfuscator import DeobfuscationResult
from core.payload_extractor import ExtractedPayload
from core.yara_synthesizer import YaraRuleSynthesizer, YaraRuleStatus


class TestYaraRuleSynthesizer:
    def test_sanitize_rule_name(self):
        assert YaraRuleSynthesizer.sanitize_rule_name("sample-123.docm") == "sample_123_docm"
        assert YaraRuleSynthesizer.sanitize_rule_name("123bad") == "rule_123bad"

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python compiler required")
    def test_synthesize_valid_yara_rule(self):
        doc = IngestedDocument(
            "test.docm", "test.docm", Path("test.docm"), 1024,
            {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
            6.2, "OpenXML", ".docm"
        )
        fused = DetectionFusionEngine.fuse([
            Finding("f1", "Win32API_VirtualAlloc", "INJECTION", "HIGH", "VirtualAlloc", "Mod1", 1, "alloc")
        ])
        deobf = [
            DeobfuscationResult("Chr(99)&...", "powershell.exe", "CHR_CONCAT", "Mod1", 5)
        ]
        payload = [
            ExtractedPayload(
                "P1", "test.docm", "Mod1", 10, 16, "hash", 4.5,
                b"\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00",
                "HEX_BUFFER", "RECOVERED", "snippet"
            )
        ]

        synth_rule = YaraRuleSynthesizer.synthesize_rule(doc, fused, deobf, payload)
        assert synth_rule.is_valid_syntax is True
        assert synth_rule.status == YaraRuleStatus.COMPILED
        assert synth_rule.compilation_error is None
        assert "powershell.exe" in synth_rule.rule_text
        assert "uint16(0) == 0x4B50" in synth_rule.rule_text

        # Test compiling and matching with yara-python (with ZIP header PK)
        compiled = yara.compile(source=synth_rule.rule_text)
        matches = compiled.match(data=b"PK\x03\x04This contains powershell.exe and VirtualAlloc inside")
        assert len(matches) == 1
        assert matches[0].rule == synth_rule.rule_name

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python compiler required")
    def test_synthesize_no_strings_hash_fallback(self):
        doc = IngestedDocument(
            "clean.docx", "clean.docx", Path("clean.docx"), 512,
            {"sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"},
            4.0, "OpenXML", ".docx"
        )
        fused = DetectionFusionEngine.fuse([])
        deobf = []
        payload = []

        synth_rule = YaraRuleSynthesizer.synthesize_rule(doc, fused, deobf, payload)
        assert synth_rule.is_valid_syntax is True
        assert "$doc_hash" in synth_rule.rule_text
        assert "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff" in synth_rule.rule_text
        assert "uint16(0) == 0x4B50 and ($doc_hash)" in synth_rule.rule_text

        # Verify compilation succeeds
        compiled = yara.compile(source=synth_rule.rule_text)
        assert compiled is not None

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python compiler required")
    def test_escape_special_characters_in_rule(self):
        doc = IngestedDocument(
            "test.docm", "test.docm", Path("test.docm"), 1024,
            {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
            6.2, "OpenXML", ".docm"
        )
        fused = DetectionFusionEngine.fuse([])
        weird_str = 'C:\\Windows\\System32\\cmd.exe /c "echo hello"'
        deobf = [DeobfuscationResult('orig', weird_str, "CONCAT", "Mod1", 1)]
        payload = []

        synth_rule = YaraRuleSynthesizer.synthesize_rule(doc, fused, deobf, payload)
        assert synth_rule.is_valid_syntax is True
        assert synth_rule.compilation_error is None

        # Ensure yara parses cleanly without syntax errors
        compiled = yara.compile(source=synth_rule.rule_text)
        assert compiled is not None

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python compiler required")
    def test_metadata_escaping_with_complex_chars(self):
        # Filename containing backslashes, double quotes, newlines, and Unicode characters
        evil_filename = 'malicious\\"doc\nwith\tsnowman_\u2603.doc'
        invalid_hash = 'not-a-valid-hex-hash'
        doc = IngestedDocument(
            evil_filename, evil_filename, Path(evil_filename), 1024,
            {"sha256": invalid_hash},
            6.2, "OLE", ".doc"
        )
        fused = DetectionFusionEngine.fuse([])
        deobf = [DeobfuscationResult('orig', 'SuspiciousMacroText', 'CONCAT', 'Mod1', 1)]
        payload = []

        synth_rule = YaraRuleSynthesizer.synthesize_rule(doc, fused, deobf, payload)
        # Invalid hash should be replaced safely
        assert "UNKNOWN_OR_UNAVAILABLE" in synth_rule.rule_text
        # Filename quotes/newlines must be escaped properly
        assert '\\"' in synth_rule.rule_text
        assert '\\n' in synth_rule.rule_text
        # Rule must still compile successfully with yara-python
        compiled = yara.compile(source=synth_rule.rule_text)
        assert compiled is not None
        assert synth_rule.is_valid_syntax is True

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python compiler required")
    def test_container_magic_ole_vs_openxml(self):
        # 1. OLE document (.doc)
        ole_doc = IngestedDocument(
            "sample.doc", "sample.doc", Path("sample.doc"), 1024,
            {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
            5.0, "OLE", ".doc"
        )
        deobf_ole = [DeobfuscationResult('orig', 'SharedWeaponPayload', 'CONCAT', 'Mod1', 1)]
        rule_ole = YaraRuleSynthesizer.synthesize_rule(ole_doc, DetectionFusionEngine.fuse([]), deobf_ole, [])
        assert "uint32(0) == 0xE011CFD0" in rule_ole.rule_text

        compiled_ole = yara.compile(source=rule_ole.rule_text)

        # OLE magic bytes: \xD0\xCF\x11\xE0
        ole_stream = b"\xd0\xcf\x11\xe0" + b"Extra data SharedWeaponPayload inside OLE"
        # ZIP magic bytes: PK\x03\x04
        zip_stream = b"PK\x03\x04" + b"Extra data SharedWeaponPayload inside ZIP"

        # OLE rule MUST match OLE stream and MUST NOT match ZIP stream
        assert len(compiled_ole.match(data=ole_stream)) == 1
        assert len(compiled_ole.match(data=zip_stream)) == 0

        # 2. OpenXML document (.docm)
        openxml_doc = IngestedDocument(
            "sample.docm", "sample.docm", Path("sample.docm"), 1024,
            {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
            5.0, "OpenXML", ".docm"
        )
        deobf_zip = [DeobfuscationResult('orig', 'SharedWeaponPayload', 'CONCAT', 'Mod1', 1)]
        rule_zip = YaraRuleSynthesizer.synthesize_rule(openxml_doc, DetectionFusionEngine.fuse([]), deobf_zip, [])
        assert "uint16(0) == 0x4B50" in rule_zip.rule_text

        compiled_zip = yara.compile(source=rule_zip.rule_text)

        # OpenXML rule MUST match ZIP stream and MUST NOT match OLE stream
        assert len(compiled_zip.match(data=zip_stream)) == 1
        assert len(compiled_zip.match(data=ole_stream)) == 0


class TestYaraWithoutCompiler:
    def test_yara_missing_dependency_simulation(self):
        """Verify behavior when yara-python compiler is unavailable."""
        doc = IngestedDocument(
            "test.docm", "test.docm", Path("test.docm"), 1024,
            {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
            6.2, "OpenXML", ".docm"
        )
        deobf = [DeobfuscationResult('orig', 'test_string', 'CONCAT', 'Mod1', 1)]

        with patch("core.yara_synthesizer.YARA_AVAILABLE", False):
            synth_rule = YaraRuleSynthesizer.synthesize_rule(
                doc, DetectionFusionEngine.fuse([]), deobf, []
            )
            # Rule must NOT be reported as valid or compiled
            assert synth_rule.is_valid_syntax is False
            assert synth_rule.status == YaraRuleStatus.GENERATED_NOT_VALIDATED
            assert synth_rule.compilation_error is not None
            assert "yara-python library is not available" in synth_rule.compilation_error
            # But the rule text must still be generated
            assert "rule " in synth_rule.rule_text
            assert "test_string" in synth_rule.rule_text


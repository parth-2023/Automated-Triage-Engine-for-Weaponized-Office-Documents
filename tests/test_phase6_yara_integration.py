"""
Test Suite for Phase 6: YARA Rule Synthesis and Validation.
"""

import pytest
from pathlib import Path
import yara

from core.ingestion import IngestedDocument
from core.fusion import DetectionFusionEngine
from core.static_analyzer import Finding
from core.deobfuscator import DeobfuscationResult
from core.payload_extractor import ExtractedPayload
from core.yara_synthesizer import YaraRuleSynthesizer


class TestYaraRuleSynthesizer:
    def test_sanitize_rule_name(self):
        assert YaraRuleSynthesizer.sanitize_rule_name("sample-123.docm") == "sample_123_docm"
        assert YaraRuleSynthesizer.sanitize_rule_name("123bad") == "rule_123bad"

    def test_synthesize_valid_yara_rule(self):
        doc = IngestedDocument("test.docm", "test.docm", Path("test.docm"), 1024, {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}, 6.2, "OpenXML", ".docm")
        fused = DetectionFusionEngine.fuse([
            Finding("f1", "Win32API_VirtualAlloc", "INJECTION", "HIGH", "VirtualAlloc", "Mod1", 1, "alloc")
        ])
        deobf = [
            DeobfuscationResult("Chr(99)&...", "powershell.exe", "CHR_CONCAT", "Mod1", 5)
        ]
        payload = [
            ExtractedPayload("P1", "test.docm", "Mod1", 10, 16, "hash", 4.5, b"\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00", "HEX_BUFFER", "RECOVERED", "snippet")
        ]

        synth_rule = YaraRuleSynthesizer.synthesize_rule(doc, fused, deobf, payload)
        assert synth_rule.is_valid_syntax is True
        assert synth_rule.compilation_error is None
        assert "powershell.exe" in synth_rule.rule_text

        # Test compiling and matching with yara-python
        compiled = yara.compile(source=synth_rule.rule_text)
        matches = compiled.match(data=b"This contains powershell.exe and VirtualAlloc inside")
        assert len(matches) == 1
        assert matches[0].rule == synth_rule.rule_name

    def test_synthesize_no_strings_hash_fallback(self):
        doc = IngestedDocument("clean.docx", "clean.docx", Path("clean.docx"), 512, {"sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"}, 4.0, "OpenXML", ".docx")
        fused = DetectionFusionEngine.fuse([])
        deobf = []
        payload = []

        synth_rule = YaraRuleSynthesizer.synthesize_rule(doc, fused, deobf, payload)
        assert synth_rule.is_valid_syntax is True
        assert "$doc_hash" in synth_rule.rule_text
        assert "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff" in synth_rule.rule_text
        assert "condition:\n        $doc_hash" in synth_rule.rule_text

        # Verify compilation succeeds
        compiled = yara.compile(source=synth_rule.rule_text)
        assert compiled is not None

    def test_escape_special_characters_in_rule(self):
        doc = IngestedDocument("test.docm", "test.docm", Path("test.docm"), 1024, {"sha256": "abc123"}, 6.2, "OpenXML", ".docm")
        fused = DetectionFusionEngine.fuse([])
        # Deobfuscated string containing backslashes, quotes, and newlines
        weird_str = 'C:\\Windows\\System32\\cmd.exe /c "echo hello"'
        deobf = [DeobfuscationResult('orig', weird_str, "CONCAT", "Mod1", 1)]
        payload = []

        synth_rule = YaraRuleSynthesizer.synthesize_rule(doc, fused, deobf, payload)
        assert synth_rule.is_valid_syntax is True
        assert synth_rule.compilation_error is None

        # Ensure yara parses cleanly without syntax errors
        compiled = yara.compile(source=synth_rule.rule_text)
        assert compiled is not None

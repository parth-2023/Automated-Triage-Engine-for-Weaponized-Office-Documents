"""
Test Suite for Phase 2: Static Detection, Detection Fusion, and Risk Assessment.
"""

import pytest
from pathlib import Path

from core.vba_extractor import VBAModule, VBAExtractionResult
from core.static_analyzer import StaticAnalyzer, Finding
from core.fusion import DetectionFusionEngine
from core.risk_engine import RiskEngine
from core.feature_extractor import FeatureExtractor
from core.ingestion import IngestedDocument
from core.document_inspector import StructuralInspectionResult


class TestStaticAnalyzer:
    def test_benign_vba(self):
        code = """Sub CalculateSum()
            Dim a As Integer
            Dim b As Integer
            a = 5
            b = 10
            MsgBox a + b
        End Sub"""
        mod = VBAModule("Mod1", "VBA/Mod1", "Mod1", code, 7, ["Sub CalculateSum"])
        findings = StaticAnalyzer.analyze_module(mod)
        assert len(findings) == 0

    def test_auto_execution_trigger(self):
        code = """Sub Document_Open()
            MsgBox "Opened"
        End Sub"""
        mod = VBAModule("Mod1", "VBA/Mod1", "Mod1", code, 3, ["Sub Document_Open"])
        findings = StaticAnalyzer.analyze_module(mod)
        assert len(findings) == 1
        assert findings[0].indicator_name == "Document_Open"
        assert findings[0].category == "EXECUTION"
        assert findings[0].line_number == 1

    def test_obfuscation_primitives(self):
        code = """Sub Obfuscated()
            Dim cmd As String
            cmd = Chr(99) & Chr(97) & Chr(108) & Chr(99)
            cmd = StrReverse("exe.ptscrsc")
        End Sub"""
        mod = VBAModule("ModObf", "VBA/ModObf", "ModObf", code, 5, ["Sub Obfuscated"])
        findings = StaticAnalyzer.analyze_module(mod)
        # Should detect Chr_Obfuscation and StrReverse
        indicators = [f.indicator_name for f in findings]
        assert "Chr_Obfuscation" in indicators
        assert "StrReverse" in indicators

    def test_win32_api_declarations(self):
        code = """Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr"""
        mod = VBAModule("ModAPI", "VBA/ModAPI", "ModAPI", code, 2, [])
        findings = StaticAnalyzer.analyze_module(mod)
        indicators = [f.indicator_name for f in findings]
        assert "Win32API_VirtualAlloc" in indicators
        assert "Win32API_CreateThread" in indicators


class TestDetectionFusion:
    def test_deduplication(self):
        finding1 = Finding("f1", "Chr_Obfuscation", "OBFUSCATION", "LOW", "Chr(65)", "Mod1", 5, "desc")
        finding2 = Finding("f2", "Chr_Obfuscation", "OBFUSCATION", "LOW", "Chr(65)", "Mod1", 5, "desc")
        fused = DetectionFusionEngine.fuse([finding1, finding2])
        assert fused.raw_finding_count == 2
        assert len(fused.deduplicated_findings) == 1

    def test_staged_loader_correlation(self):
        f_trig = Finding("f1", "Document_Open", "EXECUTION", "MEDIUM", "Document_Open", "Mod1", 1, "trigger")
        f_alloc = Finding("f2", "Win32API_VirtualAlloc", "INJECTION", "HIGH", "VirtualAlloc", "Mod1", 2, "alloc")
        f_copy = Finding("f3", "Win32API_RtlMoveMemory", "INJECTION", "HIGH", "RtlMoveMemory", "Mod1", 3, "copy")
        f_thread = Finding("f4", "Win32API_CreateThread", "INJECTION", "HIGH", "CreateThread", "Mod1", 4, "thread")

        fused = DetectionFusionEngine.fuse([f_trig, f_alloc, f_copy, f_thread])
        assert fused.has_auto_exec is True
        assert fused.has_memory_alloc is True
        assert fused.has_memory_copy is True
        assert fused.has_thread_create is True
        assert len(fused.correlated_patterns) >= 1
        assert any("Staged Memory Injection Loader" in p.pattern_name for p in fused.correlated_patterns)


class TestRiskEngine:
    def test_benign_document_score(self):
        engine = RiskEngine()
        fused = DetectionFusionEngine.fuse([])
        verdict = engine.evaluate(fused)
        assert verdict.classification == "LOW"
        assert verdict.normalized_score <= 19
        assert len(verdict.limitations) > 0

    def test_staged_loader_high_critical_score(self):
        engine = RiskEngine()
        f_trig = Finding("f1", "Document_Open", "EXECUTION", "MEDIUM", "Document_Open", "Mod1", 1, "trigger")
        f_alloc = Finding("f2", "Win32API_VirtualAlloc", "INJECTION", "HIGH", "VirtualAlloc", "Mod1", 2, "alloc")
        f_copy = Finding("f3", "Win32API_RtlMoveMemory", "INJECTION", "HIGH", "RtlMoveMemory", "Mod1", 3, "copy")
        f_thread = Finding("f4", "Win32API_CreateThread", "INJECTION", "HIGH", "CreateThread", "Mod1", 4, "thread")

        fused = DetectionFusionEngine.fuse([f_trig, f_alloc, f_copy, f_thread])
        verdict = engine.evaluate(fused)
        assert verdict.normalized_score >= 80
        assert verdict.classification == "CRITICAL"
        assert len(verdict.applied_bonuses) > 0

    def test_corrupt_inconclusive(self):
        engine = RiskEngine()
        fused = DetectionFusionEngine.fuse([])
        verdict = engine.evaluate(fused, is_valid_format=True, is_corrupt=True)
        assert verdict.classification == "INCONCLUSIVE"

    def test_incomplete_analysis_status_partial(self):
        engine = RiskEngine()
        fused = DetectionFusionEngine.fuse([])
        # Even with 0 findings, partial analysis should be marked PARTIAL
        verdict = engine.evaluate(fused, is_valid_format=True, is_corrupt=False, analysis_status="PARTIAL")
        assert verdict.classification == "PARTIAL"
        assert verdict.security_verdict == "INCOMPLETE ANALYSIS — VERDICT UNVERIFIED"
        assert any("PARTIAL" in lim for lim in verdict.limitations)

    def test_diminishing_returns_and_weights(self):
        engine = RiskEngine()
        # Create 3 instances of the same indicator
        f1 = Finding("f1", "Document_Open", "EXECUTION", "MEDIUM", "Document_Open", "Mod1", 1, "trigger")
        f2 = Finding("f2", "Document_Open", "EXECUTION", "MEDIUM", "Document_Open", "Mod1", 5, "trigger")
        f3 = Finding("f3", "Document_Open", "EXECUTION", "MEDIUM", "Document_Open", "Mod1", 10, "trigger")
        fused = DetectionFusionEngine.fuse([f1, f2, f3])
        verdict = engine.evaluate(fused)
        # Base weight for Document_Open in policy is 20
        # 1st instance: 20 * 1.0 = 20
        # 2nd instance: 20 * 0.3 = 6
        # 3rd instance: 20 * 0.1 = 2
        # Total = 28
        assert verdict.raw_score == pytest.approx(28.0, 0.5)

    def test_risk_bands(self):
        engine = RiskEngine()
        # Test low
        v_low = engine.evaluate(DetectionFusionEngine.fuse([]))
        assert v_low.classification == "LOW"
        assert 0 <= v_low.normalized_score <= 19

        # Test medium
        f_med = Finding("f1", "Document_Open", "EXECUTION", "MEDIUM", "Document_Open", "Mod1", 1, "trigger")
        v_med = engine.evaluate(DetectionFusionEngine.fuse([f_med]))
        assert v_med.classification == "MEDIUM"
        assert 20 <= v_med.normalized_score <= 49


class TestFeatureExtractor:
    def test_feature_states_and_sentinel(self):
        from core.feature_extractor import FeatureState, FeatureEntry
        doc = IngestedDocument("test.docm", "test.docm", Path("test.docm"), 1024, {"sha256": "abc"}, 6.2, "OpenXML", ".docm")
        struct = StructuralInspectionResult("OpenXML", 5, [], True, "word/vbaProject.bin", 6.8, 5.1)
        # When VBA extraction fails / has no macros:
        vba = VBAExtractionResult(False, 0, 0, [])
        fused = DetectionFusionEngine.fuse([])

        # Stomping and payload extraction were not applicable or failed
        vec = FeatureExtractor.extract_features(
            doc, struct, vba, fused,
            stomping_sdi=None, pcode_tokens=None, payload_bytes=None, resolved_api_hashes=None,
            stomping_status=FeatureState.NOT_APPLICABLE,
            pcode_status=FeatureState.NOT_APPLICABLE,
            payload_status=FeatureState.UNAVAILABLE,
            api_hash_status=FeatureState.FAILED
        )
        assert vec.f4_stomping_discrepancy.state == FeatureState.NOT_APPLICABLE
        assert vec.f6_pcode_token_count.state == FeatureState.NOT_APPLICABLE
        assert vec.f16_extracted_payload_bytes.state == FeatureState.UNAVAILABLE
        assert vec.f17_resolved_api_hash_count.state == FeatureState.FAILED

        # Check numeric list with -1.0 sentinel
        num_list_missing = vec.to_numeric_list(missing_sentinel=-1.0)
        assert len(num_list_missing) == 18
        # f4 is NOT_APPLICABLE -> should be -1.0
        assert num_list_missing[3] == -1.0
        # f6 is NOT_APPLICABLE -> should be -1.0
        assert num_list_missing[5] == -1.0
        # f16 is UNAVAILABLE -> should be -1.0
        assert num_list_missing[15] == -1.0
        # f17 is FAILED -> should be -1.0
        assert num_list_missing[16] == -1.0

        # Check default sentinel 0.0
        num_list_zero = vec.to_numeric_list(missing_sentinel=0.0)
        assert num_list_zero[3] == 0.0

    def test_feature_vector_structure(self):
        doc = IngestedDocument("test.docm", "test.docm", Path("test.docm"), 1024, {"sha256": "abc"}, 6.2, "OpenXML", ".docm")
        struct = StructuralInspectionResult("OpenXML", 5, [], True, "word/vbaProject.bin", 6.8, 5.1)
        vba = VBAExtractionResult(True, 1, 45, [])
        fused = DetectionFusionEngine.fuse([
            Finding("f1", "Win32API_VirtualAlloc", "INJECTION", "HIGH", "VirtualAlloc", "Mod1", 1, "alloc")
        ])

        vec = FeatureExtractor.extract_features(doc, struct, vba, fused, stomping_sdi=0.25, pcode_tokens=150, payload_bytes=512)
        d = vec.to_dict()
        assert len(d) == 18
        assert d["f1_file_size_bytes"] == 1024
        assert d["f2_ole_stream_count"] == 5
        assert d["f3_has_vba_project"] == 1
        assert d["f4_stomping_discrepancy"] == 0.25
        assert d["f13_has_memory_alloc_api"] == 1
        assert d["f16_extracted_payload_bytes"] == 512

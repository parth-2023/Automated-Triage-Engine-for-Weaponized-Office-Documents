"""
Test Suite for Phase 5: Shellcode Static Analysis and ROR13 API Hash Resolution.
"""

import pytest
from core.api_resolver import ror13_hash, ApiHashResolver
from core.shellcode_analyzer import ShellcodeAnalyzer


class TestApiHashResolver:
    def test_ror13_algorithm_determinism(self):
        # Verify deterministic hash output
        h_va = ror13_hash("VirtualAlloc")
        assert isinstance(h_va, int)
        assert 0 <= h_va <= 0xFFFFFFFF
        # Check standard known reference vector
        # ROR13 of "LoadLibraryA":
        h_lla = ror13_hash("LoadLibraryA")
        assert h_lla == 0xEC0E4E8E

    def test_api_resolution_lookup(self):
        resolver = ApiHashResolver()
        h_va = ror13_hash("VirtualAlloc")
        res = resolver.resolve_hash(h_va)
        assert res is not None
        assert res.api_name == "VirtualAlloc"
        assert res.module_name == "kernel32.dll"

    def test_scan_buffer_for_embedded_hashes(self):
        resolver = ApiHashResolver()
        h_va = ror13_hash("VirtualAlloc")
        h_va_bytes = h_va.to_bytes(4, byteorder="little")
        buffer = b"\x90\x90\x90" + h_va_bytes + b"\xCC\xCC"
        matches = resolver.scan_buffer_for_hashes(buffer)
        assert len(matches) == 1
        assert matches[0].api_name == "VirtualAlloc"

    def test_unresolved_hash(self):
        resolver = ApiHashResolver()
        res = resolver.resolve_hash(0x12345678)
        assert res is None

    def test_ror13_variants(self):
        resolver = ApiHashResolver()
        # 1. ROR13_API_UPPER
        h_upper = ror13_hash("VIRTUALALLOC")
        res_upper = resolver.resolve_hash(h_upper)
        assert res_upper is not None
        assert res_upper.api_name == "VirtualAlloc"
        assert res_upper.algorithm in ["ROR13_API_UPPER", "ROR13_API_ONLY"]

        # 2. ROR13_API_NULL_TERM
        h_null = ror13_hash("LoadLibraryA", include_null=True)
        res_null = resolver.resolve_hash(h_null)
        assert res_null is not None
        assert res_null.api_name == "LoadLibraryA"
        assert res_null.algorithm == "ROR13_API_NULL_TERM"

        # 3. ROR13_MOD_API_SUM
        from core.api_resolver import ror13_mod_api_sum
        h_sum = ror13_mod_api_sum("kernel32.dll", "VirtualAlloc")
        res_sum = resolver.resolve_hash(h_sum)
        assert res_sum is not None
        assert res_sum.api_name == "VirtualAlloc"
        assert res_sum.algorithm == "ROR13_MOD_API_SUM"


class TestShellcodeAnalyzer:
    def test_short_buffer(self):
        analyzer = ShellcodeAnalyzer()
        report = analyzer.analyze_buffer(b"\x90\x90\x90")
        assert report.analysis_status == "NO_CANDIDATE"
        assert report.is_likely_shellcode is False

    def test_x86_peb_traversal_shellcode(self):
        analyzer = ShellcodeAnalyzer()
        # Typical x86 shellcode snippet:
        # 31 c0       xor eax, eax
        # 64 8b 40 30 mov eax, dword ptr fs:[eax + 0x30]  (PEB lookup)
        # c3          ret
        # Pad to >= 16 bytes
        stub = b"\x31\xc0\x64\x8b\x40\x30\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90"
        report = analyzer.analyze_buffer(stub, arch_hint="x86")
        assert report.analysis_status == "COMPLETED"
        assert report.instruction_count >= 3
        assert report.is_likely_shellcode is True
        assert any("PEB Access" in h for h in report.detected_heuristics)

    def test_call_pop_delta_routine(self):
        analyzer = ShellcodeAnalyzer()
        # e8 00 00 00 00  call $+5
        # 5b              pop ebx
        # c3              ret
        stub = b"\xe8\x00\x00\x00\x00\x5b\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90"
        report = analyzer.analyze_buffer(stub, arch_hint="x86")
        assert report.is_likely_shellcode is True
        assert any("Call/Pop Delta" in h for h in report.detected_heuristics)

    def test_x64_peb_traversal_auto_arch(self):
        analyzer = ShellcodeAnalyzer()
        # Typical x64 PEB traversal snippet:
        # 48 31 c0             xor rax, rax
        # 65 48 8b 40 60       mov rax, qword ptr gs:[rax + 0x60]  (x64 PEB)
        # c3                   ret
        stub = b"\x48\x31\xc0\x65\x48\x8b\x40\x60\xc3\x90\x90\x90\x90\x90\x90\x90"
        report = analyzer.analyze_buffer(stub, arch_hint="auto")
        assert report.analysis_status == "COMPLETED"
        assert report.architecture == "x64"
        assert report.is_likely_shellcode is True
        assert any("x64 PEB Access" in h for h in report.detected_heuristics)

    def test_unsupported_architecture_rejection(self):
        analyzer = ShellcodeAnalyzer()
        stub = b"\x90" * 32
        report = analyzer.analyze_buffer(stub, arch_hint="arm64")
        assert report.analysis_status == "FAILED"
        assert "Unsupported architecture" in str(report.error)
        assert report.is_likely_shellcode is False

    def test_benign_buffer_not_classified_as_shellcode(self):
        analyzer = ShellcodeAnalyzer()
        # English sentence or regular binary data without shellcode heuristics
        benign_buf = b"This is a legitimate string of english text used as placeholder."
        report = analyzer.analyze_buffer(benign_buf, arch_hint="auto")
        assert report.is_likely_shellcode is False
        assert report.confidence == "Low"

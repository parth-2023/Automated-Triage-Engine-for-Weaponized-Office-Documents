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

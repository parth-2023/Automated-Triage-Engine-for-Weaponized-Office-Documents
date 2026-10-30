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

    def test_ror13_custom_seed_low_level_only(self):
        # ror13_hash accepts custom seed as low-level utility
        h_seed_1 = ror13_hash("VirtualAlloc", seed=0x12345678)
        h_seed_2 = ror13_hash("VirtualAlloc", seed=0x12345678)
        assert h_seed_1 == h_seed_2
        assert h_seed_1 != ror13_hash("VirtualAlloc", seed=0)

        # ApiHashResolver does NOT claim to resolve unconfigured arbitrary custom seeds
        resolver = ApiHashResolver()
        res_unseeded = resolver.resolve_hash(h_seed_1)
        assert res_unseeded is None

    def test_known_answer_reference_vectors(self):
        # Canonical reference vectors independently generated:
        # LoadLibraryA -> 0xEC0E4E8E
        assert ror13_hash("LoadLibraryA") == 0xEC0E4E8E
        # VirtualAlloc -> 0x91AFCA54
        assert ror13_hash("VirtualAlloc") == 0x91AFCA54
        # GetProcAddress -> 0x7C0DFCAA
        assert ror13_hash("GetProcAddress") == 0x7C0DFCAA


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

    def test_structured_shellcode_validation_corpus(self):
        """
        Structured static test corpus validating detection accuracy, false positive prevention,
        and false negative tracking across benign and malicious categories.
        All buffers are strictly static — no execution.
        """
        analyzer = ShellcodeAnalyzer()

        # 1. Benign executable snippets (compiler prologue, standard CRT, random data)
        # Even though Capstone disassembles prologue/epilogue instructions, they must NOT be flagged as shellcode.
        benign_prologue = (
            b"\x55"                          # push ebp
            b"\x89\xe5"                      # mov ebp, esp
            b"\x83\xec\x40"                  # sub esp, 0x40
            b"\x8b\x45\x08"                  # mov eax, [ebp + 8]
            b"\x03\x45\x0c"                  # add eax, [ebp + 0xc]
            b"\xc9"                          # leave
            b"\xc3"                          # ret
            b"\x90\x90\x90\x90\x90\x90"      # nop padding >= 16 bytes
        )
        benign_crt_stub = (
            b"\x8b\x44\x24\x04"              # mov eax, [esp + 4]
            b"\x03\x44\x24\x08"              # add eax, [esp + 8]
            b"\xc2\x08\x00"                  # ret 8
            b"\x90\x90\x90\x90\x90\x90\x90\x90\x90"
        )
        random_non_executable = b"\x7a\x1b\x9e\x4f\x03\x88\x12\xbb\x54\x91\x32\xfe\xca\x01\x88\x33\x5a\xbc\xde\xf0"

        # 2. Ordinary document bytes (XML, plain text, compressed data)
        doc_xml = b'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.org"><w:body>test</w:body></w:document>'
        doc_prose = b"Please find attached quarterly operational expenditure report. Contact accounting for inquiries."
        doc_compressed = b"\x78\x9c\x4b\xce\xcf\x2d\x28\x4a\x2d\x2e\x4e\x4d\x01\x00\x1a\x0b\x04\x5d\xaa\xbb\xcc\xdd"

        # 3. Documented shellcode patterns
        # Pattern A: x86 PEB traversal
        shellcode_x86_peb = b"\x31\xc0\x64\x8b\x40\x30\x8b\x40\x0c\x8b\x70\x1c\xc3\x90\x90\x90"
        # Pattern B: x64 PEB traversal
        shellcode_x64_peb = b"\x48\x31\xc0\x65\x48\x8b\x40\x60\x48\x8b\x40\x18\xc3\x90\x90\x90"
        # Pattern C: Call/Pop delta calculation + loop
        shellcode_call_pop = b"\xe8\x00\x00\x00\x00\x5b\x83\xc3\x10\xac\xaa\xc3\x90\x90\x90\x90"
        # Pattern D: x86 Egg Hunter (CLD + SCASD search primitive)
        shellcode_egghunter = b"\xfc\x8b\xfa\xb8\x54\x30\x30\x57\xaf\x75\xf9\xc3\x90\x90\x90\x90"

        benign_samples = [
            ("benign_prologue", benign_prologue),
            ("benign_crt_stub", benign_crt_stub),
            ("random_non_executable", random_non_executable),
            ("doc_xml", doc_xml),
            ("doc_prose", doc_prose),
            ("doc_compressed", doc_compressed),
        ]

        malicious_samples = [
            ("shellcode_x86_peb", shellcode_x86_peb, "PEB Access"),
            ("shellcode_x64_peb", shellcode_x64_peb, "x64 PEB Access"),
            ("shellcode_call_pop", shellcode_call_pop, "Call/Pop Delta"),
            ("shellcode_egghunter", shellcode_egghunter, "Egg hunter"),
        ]

        false_positives = 0
        for name, buffer in benign_samples:
            rep = analyzer.analyze_buffer(buffer, arch_hint="auto")
            # Disassembly success alone must NEVER establish shellcode classification
            if rep.is_likely_shellcode:
                false_positives += 1
            assert rep.is_likely_shellcode is False, f"False positive on benign sample: {name}"

        assert false_positives == 0, f"Expected 0 false positives, got {false_positives}"

        false_negatives = 0
        for name, buffer, expected_heuristic in malicious_samples:
            rep = analyzer.analyze_buffer(buffer, arch_hint="auto")
            if not rep.is_likely_shellcode:
                false_negatives += 1
            assert rep.is_likely_shellcode is True, f"False negative on shellcode sample: {name}"
            # Record and assert detection heuristics per sample
            assert any(expected_heuristic in h for h in rep.detected_heuristics), (
                f"Sample {name} missing expected heuristic '{expected_heuristic}'. Got: {rep.detected_heuristics}"
            )

        assert false_negatives == 0, f"Expected 0 false negatives, got {false_negatives}"

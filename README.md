# Automated Triage Engine for Weaponized Office Documents

A modular, deterministic, explainable static analysis and reverse engineering framework for analyzing potentially weaponized Microsoft Office documents without live macro execution.

Supports 19 Microsoft Office formats across Word, Excel, and PowerPoint:
- **Word:** `.doc`, `.docx`, `.docm`, `.dot`, `.dotx`, `.dotm`
- **Excel:** `.xls`, `.xlsx`, `.xlsm`, `.xlt`, `.xltx`, `.xltm`
- **PowerPoint:** `.ppt`, `.pptx`, `.pptm`, `.potx`, `.potm`, `.ppsx`, `.ppsm`

Designed for cybersecurity research engineers, SOC analysts, and malware reverse engineers.

---

## Key Features

1. **Multi-Format Ingestion & Structural Inspection (Word, Excel, PowerPoint)**:
   - Ingests legacy OLE Compound Documents (`.doc`, `.dot`, `.xls`, `.xlt`, `.ppt`) and modern OpenXML ZIP containers (`.docx`, `.docm`, `.xlsx`, `.xlsm`, `.pptx`, `.pptm`, etc.).
   - Magic byte verification (`D0 CF 11 E0` for OLE, `50 4B 03 04` for OpenXML) and internal structure analysis (`[Content_Types].xml`, `word/`, `xl/`, `ppt/`, OLE streams `WordDocument`, `Workbook`, `PowerPoint Document`).
   - Validates consistency between file extensions and internal package structures, detecting extension mismatches and disguised/renamed files.
   - Comprehensive OpenXML relationship analysis (`*.rels`) detecting external relationships, remote template injection (`attachedTemplate`), and suspicious protocol handlers (`ms-msdt:`, `search-ms:`, `file:`, UNC shares).
   - Safe inspection of embedded objects, packages, and embedded OLE streams (`word/embeddings/`, `oleObject*.bin`, `Ole10Native`).
   - In-depth defense against Zip-slip / directory traversal and Zip bomb decompression attacks.
   - Shannon entropy computed per OLE stream and ZIP entry with high-entropy alerts (> 7.0).

2. **VBA Extraction & Static Detection**:
   - Safe extraction of VBA macro modules, procedures, and code lines using `oletools.olevba`.
   - Regex and structural detection of auto-execution triggers (`AutoOpen`, `Document_Open`, `Workbook_Open`, `AutoExec`, etc.).
   - Detection of Win32 memory manipulation and injection APIs (`VirtualAlloc`, `VirtualAllocEx`, `RtlMoveMemory`, `WriteProcessMemory`, `CreateThread`, `CreateRemoteThread`).
   - Obfuscation indicator extraction (`Chr`, `ChrB`, `StrReverse`, XOR loops, string concatenations).

3. **Multi-Stage Detection Fusion**:
   - Deduplication and severity capping across modules to avoid artificial score inflation.
   - Attack pattern correlation (e.g. Staged Memory Injection Loader, Automated Payload Droppers).
   - Distinguishes direct observations from inferred behaviors.

4. **VBA Stomping Heuristic Analysis & SDI Metric**:
   - Disassembles compiled P-code tokens using `pcodedmp`.
   - Performs module-level semantic comparison between compiled P-code instructions and decompressed VBA source code to detect source-code removal or modification.
   - Computes the Stomping Discrepancy Index (SDI) [0.0 - 1.0] using weighted discrepancy scoring across missing procedures, missing modules, unreferenced strings, and unmatched calls.
   - Clearly distinguishes between verified stomping, clean source/P-code parity, missing source modules, missing P-code modules, and uncompiled or synthetic modules where P-code extraction is not performed.
   - Does not infer stomping solely because a single high-risk API name is absent from source; multi-signal corroboration is required.

5. **Restricted AST & Rule-Based Deobfuscation**:
   - Reconstructs `Chr()` / `ChrB()` concatenations with constant arithmetic evaluation.
   - Reverses `StrReverse()` encoded strings.
   - Resolves string concatenations, Base64 strings, and hexadecimal byte sequences.
   - Evaluates variable assignment chains using string-aware token substitution (never substituting variable names inside quoted string literals or escaped quotes).
   - Evaluates bounded XOR loops over statically known byte arrays.
   - Zero execution policy: evaluated safely without using unrestricted `eval()` or `exec()`.

6. **Payload Extraction & Heuristic Shellcode Disassembly**:
   - Recovers embedded byte arrays, hex buffers, and binary blobs from VBA source code and deobfuscation outputs.
   - Disassembles candidate payload buffers using the `Capstone` engine with multi-hypothesis architecture evaluation (`x86`, `x64`, or `auto`).
   - Evaluates multi-signal shellcode execution heuristics (segment register PEB traversal `fs:[0x30]` / `gs:[0x60]`, Call/Pop delta calculation routines, consecutive stack pushes, Egg hunter memory search loops).
   - Validated against a structured static corpus with 0 false positives on benign code/documents and 0 false negatives on shellcode patterns.

7. **Configurable 32-bit ROR13 API Hash Resolution**:
   - Implements 4 documented resolver variants of the canonical 32-bit ROR13 hash algorithm utilized by shellcode families:
     - `ROR13_API_ONLY` (canonical case-preserved function name, null excluded)
     - `ROR13_API_UPPER` (uppercase normalized API name)
     - `ROR13_API_NULL_TERM` (null-terminated string hashing)
     - `ROR13_MOD_API_SUM` (Metasploit stager convention combining module + API sum)
   - Low-level deterministic seeding capability supported via `ror13_hash(name, seed=...)`.
   - Precomputed database of standard Windows functions (`Kernel32`, `Ntdll`, `Urlmon`, `Ws2_32`).
   - Scans candidate binary buffers for embedded little-endian API hashes and records algorithm variant and confidence.

8. **Standardized 18-Dimensional Feature Vector & 5-State Availability Model**:
   - Strictly populates the project's standardized `[f1..f18]` feature representation for triage comparisons and ML research.
   - Supports 5 explicit feature availability states: `MEASURED`, `NOT_DETECTED`, `NOT_APPLICABLE`, `UNAVAILABLE`, `FAILED`.
   - Preserves discrete states downstream via distinct sentinels (`NOT_APPLICABLE = -1.0`, `UNAVAILABLE = -2.0`, `FAILED = -3.0`) or via `to_encoded_vector()`, preventing ambiguity with legitimate measured zeros.

9. **YARA Detection Signature Synthesis & Validation**:
   - Automatically generates YARA rules matching reconstructed strings, API declarations, and binary signatures.
   - Implements scoped condition formulation with container magic bytes (`uint32(0) == 0xE011CFD0` for OLE documents, `uint16(0) == 0x4B50` for OpenXML packages) across all 19 supported extensions to avoid false positives across container types.
   - Strict metadata escaping and hash validation preventing rule syntax corruption from complex filenames.
   - Compiles and validates rules using `yara-python`; never marks a rule as valid unless compilation succeeds (reporting `GENERATED_NOT_VALIDATED` if the compiler is unavailable).

10. **Interactive Gradio Dashboard & Exportable Reports**:
    - Modern analyst-friendly Gradio web dashboard (`app.py`) with support for uploading all 19 Word, Excel, and PowerPoint extensions.
    - Strict HTML escaping against script and tag injection.
    - Displays detected container format, package type, stream entropy, extracted macros, deobfuscation outputs, shellcode findings, external relationships, and embedded objects.
    - One-click export of structured JSON and standalone, styled HTML analyst reports.

11. **Presentation Simulation Mode (Target File SHA-256 Triggered)**:
    - Dedicated, safe demonstration mode automatically triggered when an uploaded file matches SHA-256 hash 1caa845045218fb6efd4c5cba495ff315ce8bc798f54635da1a9065f946b1edd (Invoice_September_2026.docm).
    - Produces a predefined illustrative triage report (Verdict: SUSPICIOUS, Risk Score: 85/100, Level: CRITICAL, Recommendation: IMMEDIATE ANALYST REVIEW) populated with educational indicators across all 7 tabs.
    - Preserves true measured file metadata (actual SHA-256, MD5, SHA-1, size, format, and entropy) directly computed from the uploaded file.
    - Emits prominent PRESENTATION SIMULATION warning banners across the dashboard, JSON export, and HTML report to ensure simulated findings are never confused with real analysis.
    - Zero execution boundary strictly preserved; simulated indicators never enter genuine YARA generation or model training data.

---

## 18-Feature Vector Representation

| Feature ID | Name | Description |
|---|---|---|
| `f1` | `file_size_bytes` | Total document size in bytes. |
| `f2` | `ole_stream_count` | Count of OLE streams or OpenXML entries. |
| `f3` | `has_vba_project` | Binary flag (0 or 1) indicating VBA project presence. |
| `f4` | `stomping_discrepancy` | Stomping Discrepancy Index (SDI) [0.0 - 1.0]. |
| `f5` | `source_line_count` | Total extracted VBA source lines. |
| `f6` | `pcode_token_count` | Count of disassembled P-code tokens. |
| `f7` | `max_stream_entropy` | Maximum Shannon entropy across all streams. |
| `f8` | `mean_stream_entropy` | Average Shannon entropy across all streams. |
| `f9` | `suspicious_keyword_count` | Total suspicious trigger and API keywords detected. |
| `f10` | `obfuscated_chr_count` | Count of `Chr()` / `ChrB()` obfuscation calls. |
| `f11` | `strreverse_calls` | Count of `StrReverse()` calls. |
| `f12` | `win32_api_declarations` | Count of Win32 API Declare statements. |
| `f13` | `has_memory_alloc_api` | Flag (0 or 1) indicating `VirtualAlloc` or `VirtualAllocEx`. |
| `f14` | `has_memory_copy_api` | Flag (0 or 1) indicating `RtlMoveMemory` or `WriteProcessMemory`. |
| `f15` | `has_thread_create_api` | Flag (0 or 1) indicating `CreateThread` or `CreateRemoteThread`. |
| `f16` | `extracted_payload_bytes` | Total byte size of recovered binary payloads. |
| `f17` | `resolved_api_hash_count` | Count of matched 32-bit ROR13 API hashes. |
| `f18` | `has_c2_network_indicator` | Flag (0 or 1) indicating network downloader or PowerShell stager. |

---

## System Requirements & Installation

- **Operating System**: Windows 10/11, macOS, or Linux
- **Python**: 3.10, 3.11, or 3.12 (Tested on Python 3.12.10 on Windows 11)

### Setup Instructions

1. Clone or navigate to the repository directory:
   ```powershell
   cd "C:\Users\HP\Desktop\MALWARE PROJ"
   ```

2. (Optional) Create and activate a Python virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. Install verified dependencies from `requirements.txt`:
   ```powershell
   pip install -r requirements.txt
   ```

---

## Running the Application

Launch the interactive Gradio web dashboard:
```powershell
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:7860
```

### Dashboard Usage:
1. Drag and drop any `.doc`, `.docm`, `.xls`, or `.xlsm` file into the upload zone.
2. Click **Analyze Document**.
3. View executive verdict, threat explanation, and file metadata in the primary banner.
4. Explore in-depth technical evidence across the 7 dedicated dashboard tabs:
   - **Tab 1: Document Structure & Streams**: OLE stream inventory, OpenXML parts, and Shannon entropy analysis.
   - **Tab 2: VBA Source & Modules**: Extracted VBA code, procedure listings, and raw macro inspection.
   - **Tab 3: Static Findings & Attack Fusion**: Deduplicated indicator findings and correlated multi-stage attack patterns.
   - **Tab 4: Deobfuscation & Payloads**: Reconstructed strings, variable assignments, and recovered payload buffers.
   - **Tab 5: Shellcode & API Hashes**: Capstone disassembly, PEB/Call-Pop heuristics, and resolved 32-bit ROR13 API hashes.
   - **Tab 6: 18-Feature Vector**: Standardized `[f1..f18]` vector with 5-state availability tracking.
   - **Tab 7: YARA Rule & Export**: Validated YARA rule preview, with downloads for HTML analyst reports and machine-readable JSON.

---

## Running Automated Tests

Run the full automated test suite covering all phases and end-to-end integration:
```powershell
python -m pytest tests/ -v
```

All 109 test cases across the entire test suite execute and pass:
- `tests/test_phase1_ingestion.py` (19 tests) — Container ingestion, hash computation, entropy, zip bomb defense, VBA extraction.
- `tests/test_phase2_static_detection.py` (15 tests) — Static detection, fusion, YAML-weighted risk engine, policy loading fallback transparency, 5 feature states, distinct sentinels.
- `tests/test_phase3_advanced_vba.py` (19 tests) — String-aware deobfuscator variable propagation, bounded XOR loops, module-level stomping semantic comparison, payload extraction.
- `tests/test_phase4_reporting.py` (4 tests) — Report generation, JSON schema validation, HTML export, Gradio callback.
- `tests/test_phase5_shellcode_api_hash.py` (14 tests) — 4 ROR13 variants, custom-seed verification, multi-hypothesis shellcode analysis, structured validation corpus with zero false positives/negatives.
- `tests/test_phase6_yara_integration.py` (7 tests) — YARA rule compilation, hash fallback, metadata escaping, container magic scoping (OLE vs OpenXML), compiler dependency simulation.
- `tests/test_end_to_end_pipeline.py` (8 tests) — Full pipeline execution (benign, macro, corrupt, unsupported), stage failure completeness propagation, and Gradio HTML injection defenses.

---

## Security Boundaries & Safety Notice
- **Zero Live Execution**: This triage platform performs static analysis and disassembly only. No VBA macros, shellcode instructions, or reconstructed payloads are ever executed on the host system.
- **Air-Gapped Operation**: Static analysis does not contact any external Command & Control (C2) domains or IP addresses.

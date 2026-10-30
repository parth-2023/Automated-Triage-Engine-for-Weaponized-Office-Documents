# Automated Triage Engine for Weaponized Office Documents

A modular, deterministic, explainable static analysis and reverse engineering framework for analyzing potentially weaponized Microsoft Office documents (`.doc`, `.docm`, `.xls`, `.xlsm`) without live macro execution.

Designed for cybersecurity research engineers, SOC analysts, and malware reverse engineers.

---

## Key Features

1. **Multi-Format Ingestion & Structural Inspection**:
   - Ingests legacy OLE Compound Documents (`.doc`, `.xls`) and modern OpenXML ZIP containers (`.docm`, `.xlsm`).
   - Magic byte verification (`D0 CF 11 E0` for OLE, `50 4B 03 04` for OpenXML).
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

4. **VBA Stomping Analysis & SDI Metric**:
   - Disassembles compiled P-code tokens using `pcodedmp`.
   - Compares P-code tokens against decompressed VBA source lines to detect source-code removal or modification.
   - Computes the Stomping Discrepancy Index (SDI) [0.0 - 1.0].

5. **Restricted AST & Rule-Based Deobfuscation**:
   - Reconstructs `Chr()` / `ChrB()` concatenations with constant arithmetic evaluation.
   - Reverses `StrReverse()` encoded strings.
   - Resolves string concatenations, Base64 strings, and hexadecimal byte sequences.
   - Zero execution policy: evaluated safely without using unrestricted `eval()` or `exec()`.

6. **Payload Extraction & Shellcode Disassembly**:
   - Recovers embedded byte arrays, hex buffers, and binary blobs.
   - Disassembles candidate payload buffers using the `Capstone` engine (x86 and x64).
   - Identifies shellcode execution heuristics (FS:[0x30] PEB traversal, Call/Pop delta calculation routines).

7. **Canonical 32-bit ROR13 API Hash Resolution**:
   - Implements reference 32-bit ROR13 hash calculation for Win32 API names.
   - Precomputed database of standard Windows functions (`Kernel32`, `Ntdll`, `Urlmon`, `Ws2_32`).
   - Scans candidate binary buffers for embedded little-endian API hashes.

8. **Standardized 18-Dimensional Feature Vector**:
   - Strictly populates the project's standardized `[f1..f18]` feature representation for triage comparisons and ML research.

9. **YARA Detection Signature Synthesis**:
   - Automatically generates syntactically valid YARA rules matching reconstructed strings and binary signatures.
   - Compiles and validates rules using `yara-python`.

10. **Interactive Gradio Dashboard & Exportable Reports**:
    - Modern analyst-friendly Gradio web dashboard (`app.py`).
    - One-click export of structured JSON and standalone, styled HTML analyst reports.

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
3. View results organized across 8 dedicated tabs:
   - **Executive Overview & Verdict**
   - **Document Structure & Streams**
   - **VBA Source & Modules**
   - **Static Findings & Attack Fusion**
   - **Deobfuscation & Payloads**
   - **Shellcode & API Hashes**
   - **18-Feature Vector**
   - **YARA Rule & Export** (download HTML and JSON reports)

---

## Running Automated Tests

Run the full automated test suite covering all 6 phases:
```powershell
python -m pytest tests/ -v
```

All 52 test cases across all six phases execute without errors:
- `tests/test_phase1_ingestion.py` (19 tests)
- `tests/test_phase2_static_detection.py` (10 tests)
- `tests/test_phase3_advanced_vba.py` (10 tests)
- `tests/test_phase4_reporting.py` (4 tests)
- `tests/test_phase5_shellcode_api_hash.py` (7 tests)
- `tests/test_phase6_yara_integration.py` (2 tests)

---

## Security Boundaries & Safety Notice
- **Zero Live Execution**: This triage platform performs static analysis and disassembly only. No VBA macros, shellcode instructions, or reconstructed payloads are ever executed on the host system.
- **Air-Gapped Operation**: Static analysis does not contact any external Command & Control (C2) domains or IP addresses.

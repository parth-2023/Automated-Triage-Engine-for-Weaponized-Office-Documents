# Automated Triage Engine for Weaponized Office Documents
## System Architecture & Specification

### 1. Architectural Overview
The **Automated Triage Engine for Weaponized Office Documents** is a modular, deterministic, explainable static analysis framework designed to inspect Microsoft Office documents (`.doc`, `.docm`, `.xls`, `.xlsm`) without live macro execution. It detects weaponized macro techniques, VBA stomping, string obfuscation, staged loaders, embedded shellcode, and unresolved/resolved ROR13 API hashes, producing structured findings, risk verdicts, and comprehensive analyst reports.

```
+-----------------------------------------------------------------------------------------+
|                                    INPUT DOCUMENT                                       |
|                               (.doc, .docm, .xls, .xlsm)                                |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| PHASE 1: INGESTION, INSPECTION & EXTRACTION                                             |
|  - Ingestion & Validation: Magic signature checks, zip slip / traversal checks          |
|  - Hashing: SHA-256, MD5, SHA-1                                                         |
|  - Metadata Extraction: Author, creation dates, application, revision                   |
|  - OLE / OpenXML Inspector: Stream enumeration, size, Shannon entropy per stream        |
|  - VBA Project Extractor: oletools.olevba integration for code & module streams         |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| PHASE 2: STATIC DETECTION & RISK SCORING                                                |
|  - Static Analyzer: Auto-exec triggers, Win32 API declarations, obfuscation markers     |
|  - Detection Fusion Engine: Correlates indicators, eliminates double-counting           |
|  - Risk Engine: Deterministic weighted risk scoring, severity bands, explainability     |
|  - 18-Feature Vector: Standardized [f1..f18] representation for ML and analytics       |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| PHASE 3: ADVANCED VBA ANALYSIS & PAYLOAD RECOVERY                                       |
|  - AST & Rule-Based Deobfuscator: Safe Chr(), StrReverse(), XOR, string concatenation   |
|  - VBA Stomping Detector: Source vs P-code token inspection via pcodedmp, SDI metric    |
|  - Payload Extractor: Hex buffers, byte arrays, base64 payloads, recovered binaries     |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| PHASE 5: SHELLCODE ANALYSIS & ROR13 RESOLVER                                            |
|  - Shellcode Analyzer: Capstone engine disassembling x86/x64 candidate buffers          |
|  - API Hash Resolver: Documented ROR13 Windows API hash resolution                      |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| PHASE 6: YARA SYNTHESIS & SIGNATURES                                                    |
|  - YARA Rule Synthesizer: Auto-generates syntactically validated YARA rules             |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| PHASE 4: ANALYST REPORTING & DASHBOARD                                                  |
|  - Report Generator: Structured HTML and JSON downloadable reports                      |
|  - Gradio Dashboard: Interactive UI for triage, analysis, and report generation         |
+-----------------------------------------------------------------------------------------+
```

---

### 2. Module Responsibilities & Interfaces

| Module | Location | Primary Responsibilities |
|---|---|---|
| `core.ingestion` | `core/ingestion.py` | Safe temp directory management, path traversal prevention, magic byte validation, file size limits. |
| `core.hashing` | `core/hashing.py` | SHA-256, SHA-1, MD5, and Shannon entropy computation for files and streams. |
| `core.metadata` | `core/metadata.py` | Document metadata extraction from OLE SummaryInformation and OpenXML `core.xml` / `app.xml`. |
| `core.document_inspector` | `core/document_inspector.py` | OLE CFBF stream enumeration and OpenXML ZIP inspection, structure validation. |
| `core.vba_extractor` | `core/vba_extractor.py` | Macro extraction using `oletools.olevba`, module and procedure parsing. |
| `core.static_analyzer` | `core/static_analyzer.py` | Regex and AST-based detection of auto-triggers, Win32 APIs (VirtualAlloc, CreateThread), obfuscation primitives. |
| `core.stomping_detector` | `core/stomping_detector.py` | Comparison between VBA source lines and compiled P-code tokens via `pcodedmp`, Stomping Discrepancy Index (SDI). |
| `core.deobfuscator` | `core/deobfuscator.py` | Restricted deterministic evaluator for `Chr()`, `ChrB()`, `StrReverse()`, string concatenation, and XOR without code execution. |
| `core.payload_extractor` | `core/payload_extractor.py` | Extraction and hashing of embedded hex buffers, byte arrays, and base64 payloads. |
| `core.shellcode_analyzer` | `core/shellcode_analyzer.py` | Static disassembly of candidate binary buffers using Capstone engine (x86/x64). |
| `core.api_resolver` | `core/api_resolver.py` | Reference ROR13 API hash computation and database resolution for Win32 API functions. |
| `core.fusion` | `core/fusion.py` | Evidence fusion, deduplication, correlation, and multi-stage indicator chaining. |
| `core.risk_engine` | `core/risk_engine.py` | Explainable, policy-driven risk scoring, category contributions, and verdict calculation. |
| `core.feature_extractor` | `core/feature_extractor.py` | Extracts the exact 18-dimensional feature vector `[f1..f18]` specified by the project. |
| `core.yara_synthesizer` | `core/yara_synthesizer.py` | Automated synthesis and compilation check of YARA detection rules based on verified indicators. |
| `core.report_generator` | `core/report_generator.py` | Production of structured JSON and downloadable HTML analyst reports. |
| `app` | `app.py` | Modern, responsive Gradio web dashboard for analysts. |

---

### 3. Security Boundaries & Invariants
1. **Zero Execution Policy**: Under no circumstances is VBA macro code, shellcode, or reconstructed binary data executed on the host system.
2. **Safe Archive Decompression**: OpenXML archives (`.docm`, `.xlsm`) are verified against ZIP-slip vulnerabilities, maximum entry size limits (100MB), and maximum file count (10,000) prior to reading.
3. **Restricted Expression Evaluation**: Deobfuscation uses explicit AST parsing, variable symbol tables, and bounded mathematical evaluation. Unrestricted `eval()` and `exec()` are strictly forbidden.
4. **Sanitized Path & HTML Handling**: All temporary files are stored in isolated, secure temp directories using `tempfile.TemporaryDirectory` and cleaned up immediately. In the web dashboard and exported HTML reports, all document-derived strings (filenames, macro snippets, explanations) are strictly escaped via `html.escape()` to prevent HTML and script injection attacks.
5. **No Network Calling**: Static analysis is completely air-gapped and produces no external network calls.

---

### 4. Advanced Technical Specifications

#### A. 5-State Feature Availability Model (`core/feature_extractor.py`)
To prevent ambiguity between an indicator legitimately not found versus an unperformed/failed analysis stage, the 18-dimensional feature extractor implements five distinct operational states:
- `MEASURED`: Analysis completed successfully and a valid non-zero numeric value was obtained.
- `NOT_DETECTED`: Analysis completed successfully and verified the indicator was absent (explicit 0).
- `NOT_APPLICABLE`: The feature does not apply to this document format (e.g. stomping or P-code on macro-free files).
- `UNAVAILABLE`: The required dependency or parsing capability was missing (e.g. pcodedmp or Capstone not installed).
- `FAILED`: Analysis was attempted but encountered an unhandled exception or malformed input.

For machine learning integration and downstream consumers:
- `to_numeric_list()` by default maps each non-measured state to distinct sentinels (`NOT_DETECTED=0.0`, `NOT_APPLICABLE=-1.0`, `UNAVAILABLE=-2.0`, `FAILED=-3.0`), ensuring downstream consumers never conflate distinct absence/failure states with measured zeros.
- `to_encoded_vector()` exports a complete dictionary payload preserving categorical states, feature names, and encoding metadata alongside the numeric vector.

#### B. Supported ROR13 API Hashing Variants (`core/api_resolver.py`)
The engine implements 4 explicit resolver variants of 32-bit ROR13 export hashing:
1. `ROR13_API_ONLY`: Canonical 32-bit right-rotation by 13 bits, seed 0, ASCII case-preserved, null byte excluded.
2. `ROR13_API_UPPER`: Function name converted to uppercase prior to hashing.
3. `ROR13_API_NULL_TERM`: Hashing includes trailing `\x00` null byte.
4. `ROR13_MOD_API_SUM`: Metasploit stager convention combining `(ROR13(module) + ROR13(api)) & 0xFFFFFFFF`.

The low-level helper `ror13_hash(name, seed=...)` supports non-zero seeds as a deterministic utility, but the resolver explicitly does not claim to dynamically resolve arbitrary custom seeds without a precomputed reference table.

#### C. VBA Stomping Heuristics (`core/stomping_detector.py`)
Semantic divergence is evaluated at the module level by aligning parsed P-code modules with readable VBA source modules. The detector distinguishes missing source modules, missing P-code modules, and token-level discrepancies. Cross-module verification prevents false positives when procedures are called across modules. To prevent over-interpretation, stomping is never inferred solely from an isolated high-risk API call without corroborating evidence, and SDI is explicitly heuristic.

#### D. YARA Rule Validation & Container Scoping (`core/yara_synthesizer.py`)
Generated rules include container magic byte scoping (`uint32(0) == 0xE011CFD0` for OLE documents, `uint16(0) == 0x4B50` for OpenXML / ZIP documents) to prevent cross-container false positives. Document-derived metadata (filenames, SHA-256) is sanitized and escaped against syntax injection. Rules are compiled with `yara-python` and reported as `GENERATED_NOT_VALIDATED` if the compiler is missing.

#### E. Risk Policy Transparency & Authoritative Status (`core/risk_engine.py`, `core/pipeline.py`)
- Risk Engine records an explicit `policy_status` (`DEFAULT`, `LOADED_CUSTOM`, `FALLBACK_NOT_FOUND`, `FALLBACK_PARSE_ERROR`, `FALLBACK_INVALID_SCHEMA`) and embeds fallback notes in verdicts and limitations.
- The pipeline maintains a single authoritative `stage_statuses` dictionary tracking all stages. Any stage that fails or is incomplete automatically propagates to an overall `PARTIAL` analysis status and ensures the verdict cannot be classified as clean.


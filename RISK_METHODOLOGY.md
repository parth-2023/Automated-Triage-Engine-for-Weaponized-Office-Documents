# Risk Assessment Methodology & Scoring Specification (v1.0)

## 1. Executive Summary & Design Principles
The Risk Assessment Engine for the Office Document Malware Triage Platform operates on a **deterministic, explainable, and multi-layered evidence scoring model**. It produces transparent risk assessments without relying on opaque machine learning heuristics or black-box algorithms.

### Fundamental Principles:
1. **Explainability**: Every point of the final score is directly tied to an explicit observed indicator (finding) with source line numbers, offsets, or stream names.
2. **Deduplication**: Repeated occurrences of identical indicators within the same scope (e.g., 20 calls to `Chr`) are capped and clustered to prevent artificial score inflation.
3. **Synergy & Correlation**: Attack patterns that link multiple stages (e.g., Auto-Execution + Memory Allocation + Thread Creation) trigger correlation bonuses, as combined indicators indicate staged shellcode injection rather than benign document macros.
4. **Safety from Absence**: The absence of indicators is **never** treated as proof of safety; benign documents without macros receive `LOW` risk verdicts accompanied by appropriate caveats.

---

## 2. Evidence Categories & Base Weights

Indicators are grouped into five core categories with distinct maximum score caps:

| Category | Base Weight Range | Category Cap | Description |
|---|---|---|---|
| **EXECUTION** | 20 - 35 | 40 | Auto-execution triggers (`AutoOpen`, `Document_Open`, `Workbook_Open`, `AutoExec`, `Document_Close`). |
| **INJECTION / API** | 25 - 45 | 50 | Low-level Win32 APIs declared or invoked (`VirtualAlloc`, `WriteProcessMemory`, `CreateThread`, `RtlMoveMemory`). |
| **OBFUSCATION** | 10 - 25 | 35 | Evasion tactics: string reversals, repetitive `Chr()`, string XOR transformations, high-entropy binary buffers. |
| **STOMPING** | 25 - 40 | 45 | VBA source vs P-code discrepancies detected via `pcodedmp`, Stomping Discrepancy Index (SDI). |
| **PAYLOAD / C2** | 20 - 45 | 50 | Embedded shellcode stubs, resolved ROR13 API hashes, executable byte arrays, network beaconing indicators. |

---

## 3. Severity Levels & Deduplication Rules

Each finding is assigned one of four severity levels:
- **INFO (0 pts)**: Structural metadata, benign author information, standard stream counts.
- **LOW (5 - 15 pts)**: Single obfuscation function, uncommon stream name, mildly elevated entropy (> 6.5).
- **MEDIUM (20 - 35 pts)**: Standard auto-execution trigger, multiple string obfuscations, macro stomping discrepancy without confirmed shellcode.
- **HIGH (40 - 55 pts)**: Win32 memory manipulation APIs, confirmed shellcode disassembly, reconstructed executable payload, high Stomping Discrepancy Index.
- **CRITICAL (60+ pts)**: Fully reconstructed staged loader with auto-execution, memory allocation, and thread creation.

### Deduplication Rules:
- If an indicator (e.g., `Chr()`) occurs multiple times in a module, each subsequent occurrence adds only a diminishing fraction:
  $$\text{Contribution} = \text{Base} \times \left(1 + \min(n - 1, 5) \times 0.2\right)$$
- Finding clusters under the same category cannot exceed the category cap.

---

## 4. Multi-Stage Correlation Bonuses

When indicators from distinct categories co-occur, correlation rules are evaluated:
1. **Staged Loader Correlation (+25 pts)**:
   - Condition: `EXECUTION` (e.g. `Document_Open`) + `INJECTION` (`VirtualAlloc` + `RtlMoveMemory` or `CreateThread`).
   - Rationale: High-probability in-memory payload execution technique.
2. **Obfuscated Payload Drop (+20 pts)**:
   - Condition: `OBFUSCATION` (reconstructed strings / XOR) + `PAYLOAD` (embedded byte array or binary buffer).
   - Rationale: Concealed payload unpacking.
3. **Stomped Macro with Shellcode (+30 pts)**:
   - Condition: `STOMPING` (P-code divergence) + `PAYLOAD` (Capstone-verified shellcode stub).
   - Rationale: Stealth attack targeting compile-only execution while presenting benign source code.

---

## 5. Score Normalization & Risk Bands

The raw accumulated score $S_{\text{raw}}$ is normalized to a $[0, 100]$ scale:
$$\text{Final Score} = \min(100, S_{\text{raw}})$$

### Risk Classifications:
| Normalized Score | Classification | Analyst Action / Summary |
|---|---|---|
| **0 - 19** | **LOW** | No significant malicious indicators detected. Standard macro or clean document. |
| **20 - 49** | **MEDIUM** | Suspicious indicators present (e.g., auto-run or obfuscation) requiring analyst review. |
| **50 - 79** | **HIGH** | Strong evidence of malicious behavior (APIs, payload buffers, or stomping). |
| **80 - 100** | **CRITICAL** | High-confidence weaponized document with correlated multi-stage execution indicators. |

### Special Operational Statuses:
- **INCONCLUSIVE**: File is encrypted, password-protected, or partially corrupt, preventing macro stream analysis.
- **UNSUPPORTED FORMAT**: Document signature does not match supported OLE/OpenXML formats.
- **ANALYSIS INCOMPLETE**: Resource limits exceeded or parser error encountered on a specific stream.

---

## 6. Configurable Policy File
All weights, category caps, correlation bonuses, and classification thresholds are externalized in `policies/risk_policy.yaml` allowing operational teams to tune thresholds without modifying core code.

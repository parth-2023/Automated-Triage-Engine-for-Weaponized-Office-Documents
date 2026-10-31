"""
Risk Assessment Engine.

Calculates explainable, deterministic risk scores and verdicts based on
fused security findings, category caps, and correlation bonuses.

SCORING MODEL (documented):
  1. Each finding contributes its severity-mapped base weight to its category bucket.
     Severity weights: INFO=0, LOW=10, MEDIUM=20, HIGH=35, CRITICAL=50
  2. Duplicate indicators (same indicator_name) receive diminishing returns:
       1st occurrence: 100 % of base weight
       2nd occurrence: 30 %
       3rd+ occurrence: 10 %
  3. Each category bucket is capped at its configured maximum.
     Caps prevent a single category from dominating the total.
  4. Correlation bonuses are added for multi-stage attack patterns.
  5. Raw score = sum of capped category scores + correlation bonuses.
  6. Normalised score = min(100, round(raw_score)).
  7. Risk bands (thresholds configurable via YAML policy):
       LOW      [0..19]
       MEDIUM   [20..49]
       HIGH     [50..79]
       CRITICAL [80..100]

INCOMPLETE ANALYSIS HANDLING:
  When analysis_status is PARTIAL or when incomplete_features is non-empty,
  the verdict classification carries an additional warning in its limitations
  list. The classification is NOT automatically lowered — a document with
  only partial analysis and zero findings receives classification LOW but
  its limitations explicitly state the analysis was incomplete.

NOTE: These weights are heuristic values chosen for security triage.
They are not statistically validated thresholds.
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import yaml

from core.fusion import FusedDetectionResult


class PolicyLoadingStatus:
    DEFAULT = "DEFAULT"                                # Builtin default policy
    LOADED_CUSTOM = "LOADED_CUSTOM"                    # Custom YAML policy loaded successfully
    FALLBACK_NOT_FOUND = "FALLBACK_NOT_FOUND"          # Specified YAML file does not exist
    FALLBACK_PARSE_ERROR = "FALLBACK_PARSE_ERROR"      # YAML syntax/parsing error
    FALLBACK_INVALID_SCHEMA = "FALLBACK_INVALID_SCHEMA"# YAML was empty or not a mapping


@dataclass
class RiskAssessmentVerdict:
    """Complete, explainable risk assessment output."""
    raw_score: float
    normalized_score: int                      # 0 to 100
    classification: str                        # "LOW", "MEDIUM", "HIGH", "CRITICAL", "INCONCLUSIVE", "UNSUPPORTED"
    security_verdict: str                      # Human-readable verdict separate from classification
    category_scores: Dict[str, float]
    applied_bonuses: List[Dict[str, Any]]
    explanation: str
    analysis_status: str = "COMPLETED"         # reflects pipeline analysis completeness
    limitations: List[str] = field(default_factory=list)
    policy_status: str = PolicyLoadingStatus.DEFAULT
    policy_source: str = "BUILTIN_DEFAULT"
    policy_error: Optional[str] = None


DEFAULT_POLICY = {
    "thresholds": {"low_max": 19, "medium_max": 49, "high_max": 79, "critical_min": 80},
    "category_caps": {"EXECUTION": 40, "INJECTION": 50, "OBFUSCATION": 35, "STOMPING": 45, "PAYLOAD": 50},
    "severity_weights": {"INFO": 0, "LOW": 10, "MEDIUM": 20, "HIGH": 35, "CRITICAL": 50},
    "diminishing_returns": {"first": 1.0, "second": 0.3, "subsequent": 0.1},
    "base_weights": {
        "auto_open": 20, "document_open": 20, "workbook_open": 20, "auto_exec": 25, "document_close": 15,
        "virtual_alloc": 30, "virtual_alloc_ex": 35, "rtl_move_memory": 25, "write_process_memory": 35,
        "create_thread": 30, "create_remote_thread": 40, "shell_execute": 20, "win_exec": 20,
        "chr_obfuscation": 15, "str_reverse": 15, "xor_transform": 20, "high_entropy_stream": 15,
        "stomping_discrepancy_low": 15, "stomping_discrepancy_med": 25, "stomping_discrepancy_high": 40,
        "extracted_payload": 30, "shellcode_detected": 40, "resolved_api_hash": 25, "c2_network_indicator": 30,
        "remote_template_injection": 35, "embedded_ole_object": 25, "suspicious_protocol_handler": 30,
        "external_relationship": 15, "extension_mismatch": 15
    },
    "correlation_bonuses": {
        "staged_loader": 25, "obfuscated_payload": 20, "stomped_shellcode": 30
    }
}


class RiskEngine:
    """Deterministic, policy-driven risk scoring engine."""

    def __init__(self, policy_path: Optional[Path] = None):
        self.policy_path = policy_path
        self.policy = DEFAULT_POLICY
        self.policy_status = PolicyLoadingStatus.DEFAULT
        self.policy_source = "BUILTIN_DEFAULT"
        self.policy_error: Optional[str] = None

        if policy_path is not None:
            path_obj = Path(policy_path)
            if not path_obj.exists():
                self.policy_status = PolicyLoadingStatus.FALLBACK_NOT_FOUND
                self.policy_source = "FALLBACK_DEFAULT"
                self.policy_error = f"Policy file not found: {path_obj}"
            else:
                try:
                    with open(path_obj, "r", encoding="utf-8") as f:
                        loaded = yaml.safe_load(f)
                    if loaded and isinstance(loaded, dict):
                        self.policy = loaded
                        self.policy_status = PolicyLoadingStatus.LOADED_CUSTOM
                        self.policy_source = f"FILE: {path_obj.name}"
                        self.policy_error = None
                    else:
                        self.policy_status = PolicyLoadingStatus.FALLBACK_INVALID_SCHEMA
                        self.policy_source = "FALLBACK_DEFAULT"
                        self.policy_error = "Policy file was empty or did not contain a valid mapping."
                except Exception as e:
                    self.policy_status = PolicyLoadingStatus.FALLBACK_PARSE_ERROR
                    self.policy_source = "FALLBACK_DEFAULT"
                    self.policy_error = f"YAML parse error: {str(e)}"

    def _get_indicator_weight(self, indicator_name: str, severity: str) -> float:
        """
        Resolve base weight from YAML policy's base_weights table,
        falling back to severity_weights if indicator is not explicitly listed.
        """
        base_weights = self.policy.get("base_weights", DEFAULT_POLICY.get("base_weights", {}))
        severity_weights = self.policy.get("severity_weights", DEFAULT_POLICY.get("severity_weights", {}))

        # Normalize indicator name: e.g. "Win32API_VirtualAlloc" -> "virtual_alloc"
        norm = indicator_name.lower().replace("win32api_", "").replace("-", "_").strip()
        # Direct lookup or clean lookup
        mapping = {
            "document_open": "document_open",
            "documentopen": "document_open",
            "autoopen": "auto_open",
            "auto_open": "auto_open",
            "workbook_open": "workbook_open",
            "workbookopen": "workbook_open",
            "autoexec": "auto_exec",
            "auto_exec": "auto_exec",
            "document_close": "document_close",
            "documentclose": "document_close",
            "virtualalloc": "virtual_alloc",
            "virtual_alloc": "virtual_alloc",
            "virtualallocex": "virtual_alloc_ex",
            "virtual_alloc_ex": "virtual_alloc_ex",
            "rtlmovememory": "rtl_move_memory",
            "rtl_move_memory": "rtl_move_memory",
            "writeprocessmemory": "write_process_memory",
            "write_process_memory": "write_process_memory",
            "createthread": "create_thread",
            "create_thread": "create_thread",
            "createremotethread": "create_remote_thread",
            "create_remote_thread": "create_remote_thread",
            "shellexecute": "shell_execute",
            "shell_execute": "shell_execute",
            "winexec": "win_exec",
            "win_exec": "win_exec",
            "chr_obfuscation": "chr_obfuscation",
            "strreverse": "str_reverse",
            "str_reverse": "str_reverse",
            "xor_transform": "xor_transform",
            "high_entropy_stream": "high_entropy_stream",
            "extracted_payload": "extracted_payload",
            "embeddedshellcode": "shellcode_detected",
            "shellcode_detected": "shellcode_detected",
            "resolved_api_hash": "resolved_api_hash",
            "c2_network_indicator": "c2_network_indicator",
            "stomping_discrepancy_low": "stomping_discrepancy_low",
            "stomping_discrepancy_med": "stomping_discrepancy_med",
            "stomping_discrepancy_high": "stomping_discrepancy_high",
            "remotetemplateinjection": "remote_template_injection",
            "remote_template_injection": "remote_template_injection",
            "embeddedoleobject": "embedded_ole_object",
            "embedded_ole_object": "embedded_ole_object",
            "suspiciousprotocolhandler": "suspicious_protocol_handler",
            "suspicious_protocol_handler": "suspicious_protocol_handler",
            "externalrelationship": "external_relationship",
            "external_relationship": "external_relationship",
            "extensionmismatch": "extension_mismatch",
            "extension_mismatch": "extension_mismatch",
        }
        mapped_key = mapping.get(norm, norm)
        if mapped_key in base_weights:
            return float(base_weights[mapped_key])

        return float(severity_weights.get(severity, 15))

    def evaluate(
        self,
        fused_result: FusedDetectionResult,
        is_valid_format: bool = True,
        is_corrupt: bool = False,
        analysis_status: str = "COMPLETED",
        incomplete_features: Optional[List[str]] = None,
    ) -> RiskAssessmentVerdict:
        """
        Evaluate fused findings into an explainable risk score and verdict.

        Parameters
        ----------
        fused_result       : Fused detection result from DetectionFusionEngine.
        is_valid_format    : False if the file signature was not recognised.
        is_corrupt         : True if the document container was malformed.
        analysis_status    : Pipeline-level status (COMPLETED, PARTIAL, FAILED, …).
        incomplete_features: List of feature names that could not be measured.
        """
        limitations: List[str] = []
        if incomplete_features:
            limitations.extend(incomplete_features)

        if not is_valid_format:
            return RiskAssessmentVerdict(
                raw_score=0,
                normalized_score=0,
                classification="UNSUPPORTED",
                security_verdict="UNSUPPORTED FORMAT",
                category_scores={},
                applied_bonuses=[],
                explanation="File signature does not match supported OLE/OpenXML formats. Analysis cannot proceed.",
                analysis_status="UNSUPPORTED",
                limitations=["Format validation failed — file is not a recognised Office document."],
                policy_status=self.policy_status,
                policy_source=self.policy_source,
                policy_error=self.policy_error
            )

        if is_corrupt:
            return RiskAssessmentVerdict(
                raw_score=0,
                normalized_score=0,
                classification="INCONCLUSIVE",
                security_verdict="INCONCLUSIVE",
                category_scores={},
                applied_bonuses=[],
                explanation="Document structure is malformed or corrupt. Analysis is inconclusive.",
                analysis_status="INVALID_INPUT",
                limitations=["Container structure could not be parsed."],
                policy_status=self.policy_status,
                policy_source=self.policy_source,
                policy_error=self.policy_error
            )

        # Retrieve policy parameters
        severity_weights = self.policy.get("severity_weights", DEFAULT_POLICY["severity_weights"])
        caps = self.policy.get("category_caps", DEFAULT_POLICY["category_caps"])
        bonuses_config = self.policy.get("correlation_bonuses", DEFAULT_POLICY["correlation_bonuses"])
        dim_ret = self.policy.get("diminishing_returns", DEFAULT_POLICY["diminishing_returns"])

        # --- Tally scores by category with diminishing returns on repetition ---
        indicator_counts: Dict[str, int] = {}
        category_raw_scores: Dict[str, float] = {
            "EXECUTION": 0.0, "INJECTION": 0.0, "OBFUSCATION": 0.0, "STOMPING": 0.0, "PAYLOAD": 0.0
        }

        for finding in fused_result.deduplicated_findings:
            ind_name = finding.indicator_name
            cat = finding.category
            if cat not in category_raw_scores:
                category_raw_scores[cat] = 0.0

            count = indicator_counts.get(ind_name, 0)
            indicator_counts[ind_name] = count + 1

            # Base weight: from policy base_weights, falling back to severity_weights
            base_w = self._get_indicator_weight(ind_name, finding.severity)
            # Diminishing returns
            if count == 0:
                multiplier = dim_ret.get("first", 1.0)
            elif count == 1:
                multiplier = dim_ret.get("second", 0.3)
            else:
                multiplier = dim_ret.get("subsequent", 0.1)

            contribution = base_w * multiplier
            category_raw_scores[cat] += contribution

        # Apply category caps
        capped_category_scores: Dict[str, float] = {}
        for cat, raw_sc in category_raw_scores.items():
            cap = caps.get(cat, 50)
            capped_category_scores[cat] = round(min(raw_sc, cap), 1)

        total_base_score = sum(capped_category_scores.values())

        # Evaluate correlation bonuses
        applied_bonuses: List[Dict[str, Any]] = []
        bonus_total = 0.0

        for pat in fused_result.correlated_patterns:
            if "Staged Memory" in pat.pattern_name:
                b_val = bonuses_config.get("staged_loader", 25)
                applied_bonuses.append({
                    "name": pat.pattern_name,
                    "bonus": b_val,
                    "reason": "Correlated staged memory injection loader behavior."
                })
                bonus_total += b_val
            elif "Automated Payload Downloader" in pat.pattern_name:
                b_val = bonuses_config.get("obfuscated_payload", 20)
                applied_bonuses.append({
                    "name": pat.pattern_name,
                    "bonus": b_val,
                    "reason": "Auto-execution paired with payload dropper indicators."
                })
                bonus_total += b_val
            elif "Stomping" in pat.pattern_name:
                b_val = bonuses_config.get("stomped_shellcode", 30)
                applied_bonuses.append({
                    "name": pat.pattern_name,
                    "bonus": b_val,
                    "reason": "VBA stomping divergence paired with suspicious instructions."
                })
                bonus_total += b_val

        raw_score = total_base_score + bonus_total
        normalized = min(100, int(round(raw_score)))

        thresholds = self.policy.get("thresholds", DEFAULT_POLICY["thresholds"])
        if normalized <= thresholds.get("low_max", 19):
            classification = "LOW"
            security_verdict = "NO SUSPICIOUS INDICATORS DETECTED"
            explanation = (
                "No weaponization indicators were detected by the available analysis methods. "
                "This does not exclude the possibility of zero-day exploits or techniques "
                "that static analysis cannot detect."
            )
        elif normalized <= thresholds.get("medium_max", 49):
            classification = "MEDIUM"
            security_verdict = "SUSPICIOUS — REVIEW RECOMMENDED"
            explanation = (
                "Suspicious attributes detected (auto-run triggers or mild obfuscation) "
                "warranting analyst review."
            )
        elif normalized <= thresholds.get("high_max", 79):
            classification = "HIGH"
            security_verdict = "HIGH THREAT — ANALYST ACTION REQUIRED"
            explanation = (
                "High-confidence weaponization indicators identified (Win32 memory manipulation APIs, "
                "high entropy payloads, or shellcode patterns)."
            )
        else:
            classification = "CRITICAL"
            security_verdict = "CRITICAL THREAT — CONTAIN IMMEDIATELY"
            explanation = (
                "Severe threat: Correlated staged loader or multi-stage injection detected. "
                "Highly likely malicious weaponized document."
            )

        # --- Incomplete analysis warnings and verdict adjustment ---
        if analysis_status == "PARTIAL":
            # A PARTIAL analysis status ALWAYS overrides classification to "PARTIAL"
            # regardless of the computed score.  A document that could not be fully
            # analysed must NOT be presented with a confident threat band.
            classification = "PARTIAL"
            security_verdict = (
                "INCOMPLETE ANALYSIS — VERDICT UNVERIFIED"
                if normalized <= thresholds.get("low_max", 19)
                else f"INCOMPLETE ANALYSIS ({security_verdict})"
            )
            explanation = (
                "One or more analysis stages could not be completed. "
                "The risk score reflects only the evidence that was successfully obtained. "
                "The document may pose a higher risk than the score indicates."
            )

            limitations.append(
                "INCOMPLETE ANALYSIS (PARTIAL): One or more analysis stages could not be completed. "
                "The risk verdict reflects only the evidence that was successfully obtained. "
                "The document may pose a higher risk than the score indicates."
            )
        elif not fused_result.deduplicated_findings:
            limitations.append(
                "No macro streams or suspicious structures detected. "
                "Absence of indicators does not guarantee safety from zero-day exploits."
            )

        if self.policy_status in (
            PolicyLoadingStatus.FALLBACK_NOT_FOUND,
            PolicyLoadingStatus.FALLBACK_PARSE_ERROR,
            PolicyLoadingStatus.FALLBACK_INVALID_SCHEMA
        ):
            limitations.append(
                f"Risk policy configuration fallback: {self.policy_status} ({self.policy_error}). Using default policy."
            )

        return RiskAssessmentVerdict(
            raw_score=round(raw_score, 1),
            normalized_score=normalized,
            classification=classification,
            security_verdict=security_verdict,
            category_scores=capped_category_scores,
            applied_bonuses=applied_bonuses,
            explanation=explanation,
            analysis_status=analysis_status,
            limitations=limitations,
            policy_status=self.policy_status,
            policy_source=self.policy_source,
            policy_error=self.policy_error
        )

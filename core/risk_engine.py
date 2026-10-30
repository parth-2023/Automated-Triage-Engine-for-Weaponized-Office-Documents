"""
Risk Assessment Engine.
Calculates explainable, deterministic risk scores and verdicts based on
fused security findings, category caps, and correlation bonuses.
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import yaml

from core.fusion import FusedDetectionResult


@dataclass
class RiskAssessmentVerdict:
    """Complete, explainable risk assessment output."""
    raw_score: float
    normalized_score: int  # 0 to 100
    classification: str    # "LOW", "MEDIUM", "HIGH", "CRITICAL", "INCONCLUSIVE", "UNSUPPORTED"
    category_scores: Dict[str, float]
    applied_bonuses: List[Dict[str, Any]]
    explanation: str
    limitations: List[str] = field(default_factory=list)


DEFAULT_POLICY = {
    "thresholds": {"low_max": 19, "medium_max": 49, "high_max": 79, "critical_min": 80},
    "category_caps": {"EXECUTION": 40, "INJECTION": 50, "OBFUSCATION": 35, "STOMPING": 45, "PAYLOAD": 50},
    "base_weights": {
        "auto_open": 20, "document_open": 20, "workbook_open": 20, "auto_exec": 25, "document_close": 15,
        "virtual_alloc": 30, "virtual_alloc_ex": 35, "rtl_move_memory": 25, "write_process_memory": 35,
        "create_thread": 30, "create_remote_thread": 40, "shell_execute": 20, "win_exec": 20,
        "chr_obfuscation": 15, "str_reverse": 15, "xor_transform": 20, "high_entropy_stream": 15,
        "stomping_discrepancy_low": 15, "stomping_discrepancy_med": 25, "stomping_discrepancy_high": 40,
        "extracted_payload": 30, "shellcode_detected": 40, "resolved_api_hash": 25, "c2_network_indicator": 30
    },
    "correlation_bonuses": {
        "staged_loader": 25, "obfuscated_payload": 20, "stomped_shellcode": 30
    }
}


class RiskEngine:
    """Deterministic, policy-driven risk scoring engine."""

    def __init__(self, policy_path: Optional[Path] = None):
        self.policy = DEFAULT_POLICY
        if policy_path and policy_path.exists():
            try:
                with open(policy_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if loaded and isinstance(loaded, dict):
                        self.policy = loaded
            except Exception:
                pass  # Fall back to default policy

    def evaluate(self, fused_result: FusedDetectionResult, is_valid_format: bool = True, is_corrupt: bool = False) -> RiskAssessmentVerdict:
        """
        Evaluate fused findings into an explainable risk score and verdict.
        """
        limitations = []
        if not is_valid_format:
            return RiskAssessmentVerdict(
                raw_score=0,
                normalized_score=0,
                classification="UNSUPPORTED FORMAT",
                category_scores={},
                applied_bonuses=[],
                explanation="File signature does not match supported OLE/OpenXML formats. Analysis cannot proceed.",
                limitations=["Format validation failed."]
            )

        if is_corrupt:
            return RiskAssessmentVerdict(
                raw_score=0,
                normalized_score=0,
                classification="INCONCLUSIVE",
                category_scores={},
                applied_bonuses=[],
                explanation="Document structure is malformed or corrupt. Analysis is inconclusive.",
                limitations=["Container structure could not be parsed."]
            )

        weights = self.policy.get("base_weights", DEFAULT_POLICY["base_weights"])
        caps = self.policy.get("category_caps", DEFAULT_POLICY["category_caps"])
        bonuses_config = self.policy.get("correlation_bonuses", DEFAULT_POLICY["correlation_bonuses"])

        # Tally scores by category with diminishing returns on repetition
        indicator_counts: Dict[str, int] = {}
        category_raw_scores: Dict[str, float] = {
            "EXECUTION": 0.0, "INJECTION": 0.0, "OBFUSCATION": 0.0, "STOMPING": 0.0, "PAYLOAD": 0.0
        }

        severity_weight_map = {
            "INFO": 0, "LOW": 10, "MEDIUM": 20, "HIGH": 35, "CRITICAL": 50
        }

        for finding in fused_result.deduplicated_findings:
            ind_name = finding.indicator_name
            cat = finding.category
            if cat not in category_raw_scores:
                category_raw_scores[cat] = 0.0

            # Count occurrences of this specific indicator
            count = indicator_counts.get(ind_name, 0)
            indicator_counts[ind_name] = count + 1

            base_w = severity_weight_map.get(finding.severity, 15)
            # Diminishing return factor: 1st occurrence = 100%, 2nd = 30%, 3rd = 15%, etc.
            multiplier = 1.0 if count == 0 else (0.3 if count == 1 else 0.1)
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
            explanation = "Document exhibits minimal or benign behavior. No weaponization indicators observed."
        elif normalized <= thresholds.get("medium_max", 49):
            classification = "MEDIUM"
            explanation = "Suspicious attributes detected (such as auto-run triggers or mild obfuscation) warranting analyst review."
        elif normalized <= thresholds.get("high_max", 79):
            classification = "HIGH"
            explanation = "High-confidence weaponization indicators identified (Win32 memory manipulation APIs, high entropy payloads, or shellcode patterns)."
        else:
            classification = "CRITICAL"
            explanation = "Severe threat: Correlated staged loader or multi-stage injection detected. Highly likely malicious weaponized document."

        if not fused_result.deduplicated_findings:
            limitations.append("No macro streams or suspicious structures detected. Absence of indicators does not guarantee safety from zero-day exploits.")

        return RiskAssessmentVerdict(
            raw_score=round(raw_score, 1),
            normalized_score=normalized,
            classification=classification,
            category_scores=capped_category_scores,
            applied_bonuses=applied_bonuses,
            explanation=explanation,
            limitations=limitations
        )

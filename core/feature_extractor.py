"""
18-Dimensional Feature Vector Extractor.

Extracts the standardized [f1..f18] feature representation defined in the project specification
for structured reporting, historical triage comparison, and optional ML evaluation.

DESIGN NOTE — Feature Availability:
Every advanced feature can be in one of five states:
  - MEASURED        : Analysis completed and a numeric value was obtained.
  - NOT_DETECTED    : Analysis completed; the feature was not present (explicit 0).
  - NOT_APPLICABLE  : The feature does not apply to this document format.
  - UNAVAILABLE     : The required dependency or parsing capability was missing.
  - FAILED          : Analysis was attempted but raised an error.

The raw value field stores the numeric value when state is MEASURED or NOT_DETECTED.
When state is UNAVAILABLE or FAILED the numeric value is None so that it is never
confused with a legitimate measured zero.

The to_numeric_list() conversion layer handles None values explicitly for any downstream
ML pipeline — it uses -1 as a sentinel rather than 0, and documents this convention.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional

from core.ingestion import IngestedDocument
from core.document_inspector import StructuralInspectionResult
from core.vba_extractor import VBAExtractionResult
from core.fusion import FusedDetectionResult

# ---------------------------------------------------------------------------
# Feature availability states
# ---------------------------------------------------------------------------

class FeatureState:
    MEASURED       = "MEASURED"        # completed; value is valid
    NOT_DETECTED   = "NOT_DETECTED"    # completed; indicator absent (value == 0 or False)
    NOT_APPLICABLE = "NOT_APPLICABLE"  # document type does not support this feature
    UNAVAILABLE    = "UNAVAILABLE"     # dependency missing or analysis not attempted
    FAILED         = "FAILED"          # analysis attempted but errored


@dataclass
class FeatureEntry:
    """Single feature with its value AND availability state."""
    name: str
    value: Optional[float]       # None when state is UNAVAILABLE or FAILED
    state: str                   # one of FeatureState constants
    note: str = ""               # human-readable explanation of state when not MEASURED

    def to_display(self) -> str:
        if self.value is None:
            return f"[{self.state}]"
        return str(self.value)


@dataclass
class DocumentFeatureVector:
    """
    Standardized 18-feature representation with per-feature availability states.

    Feature names (order preserved from original specification):
      f1  file_size_bytes
      f2  ole_stream_count
      f3  has_vba_project
      f4  stomping_discrepancy
      f5  source_line_count
      f6  pcode_token_count
      f7  max_stream_entropy
      f8  mean_stream_entropy
      f9  suspicious_keyword_count
      f10 obfuscated_chr_count
      f11 strreverse_calls
      f12 win32_api_declarations
      f13 has_memory_alloc_api
      f14 has_memory_copy_api
      f15 has_thread_create_api
      f16 extracted_payload_bytes
      f17 resolved_api_hash_count
      f18 has_c2_network_indicator
    """
    f1_file_size_bytes:          FeatureEntry
    f2_ole_stream_count:         FeatureEntry
    f3_has_vba_project:          FeatureEntry
    f4_stomping_discrepancy:     FeatureEntry
    f5_source_line_count:        FeatureEntry
    f6_pcode_token_count:        FeatureEntry
    f7_max_stream_entropy:       FeatureEntry
    f8_mean_stream_entropy:      FeatureEntry
    f9_suspicious_keyword_count: FeatureEntry
    f10_obfuscated_chr_count:    FeatureEntry
    f11_strreverse_calls:        FeatureEntry
    f12_win32_api_declarations:  FeatureEntry
    f13_has_memory_alloc_api:    FeatureEntry
    f14_has_memory_copy_api:     FeatureEntry
    f15_has_thread_create_api:   FeatureEntry
    f16_extracted_payload_bytes: FeatureEntry
    f17_resolved_api_hash_count: FeatureEntry
    f18_has_c2_network_indicator: FeatureEntry

    # Track whether any advanced analysis was unavailable / failed
    analysis_complete: bool = True
    unavailable_features: List[str] = field(default_factory=list)
    failed_features: List[str] = field(default_factory=list)

    def _feature_list(self) -> List[FeatureEntry]:
        return [
            self.f1_file_size_bytes,
            self.f2_ole_stream_count,
            self.f3_has_vba_project,
            self.f4_stomping_discrepancy,
            self.f5_source_line_count,
            self.f6_pcode_token_count,
            self.f7_max_stream_entropy,
            self.f8_mean_stream_entropy,
            self.f9_suspicious_keyword_count,
            self.f10_obfuscated_chr_count,
            self.f11_strreverse_calls,
            self.f12_win32_api_declarations,
            self.f13_has_memory_alloc_api,
            self.f14_has_memory_copy_api,
            self.f15_has_thread_create_api,
            self.f16_extracted_payload_bytes,
            self.f17_resolved_api_hash_count,
            self.f18_has_c2_network_indicator,
        ]

    def to_dict(self) -> Dict[str, Any]:
        """
        Return a flat dict keyed by feature name.
        The value is the numeric value when available, or the state string otherwise.
        """
        out: Dict[str, Any] = {}
        for fe in self._feature_list():
            out[fe.name] = fe.value if fe.value is not None else f"[{fe.state}]"
        return out

    def to_detail_dict(self) -> Dict[str, Dict[str, Any]]:
        """Return full detail (value + state + note) for every feature."""
        out: Dict[str, Dict[str, Any]] = {}
        for fe in self._feature_list():
            out[fe.name] = {"value": fe.value, "state": fe.state, "note": fe.note}
        return out

    def to_numeric_list(self, missing_sentinel: float = -1.0) -> List[float]:
        """
        Convert features to a numeric list for ML pipelines.

        Convention:
          - MEASURED / NOT_DETECTED → actual numeric value
          - UNAVAILABLE / FAILED / NOT_APPLICABLE → missing_sentinel (default -1.0)

        Callers must be aware that -1.0 does NOT mean zero.
        """
        result = []
        for fe in self._feature_list():
            if fe.value is not None:
                result.append(float(fe.value))
            else:
                result.append(missing_sentinel)
        return result

    # Legacy compatibility shim — returns same shape as old to_dict()
    def to_list(self) -> List[Any]:
        return [fe.value for fe in self._feature_list()]


# ---------------------------------------------------------------------------
# Helper to build a FeatureEntry
# ---------------------------------------------------------------------------

def _fe(name: str, value: Optional[float], state: str, note: str = "") -> FeatureEntry:
    return FeatureEntry(name=name, value=value, state=state, note=note)


def _measured(name: str, value: float) -> FeatureEntry:
    state = FeatureState.MEASURED if value != 0 else FeatureState.NOT_DETECTED
    return FeatureEntry(name=name, value=value, state=state)


def _unavailable(name: str, note: str) -> FeatureEntry:
    return FeatureEntry(name=name, value=None, state=FeatureState.UNAVAILABLE, note=note)


def _failed(name: str, note: str) -> FeatureEntry:
    return FeatureEntry(name=name, value=None, state=FeatureState.FAILED, note=note)


def _not_applicable(name: str, note: str) -> FeatureEntry:
    return FeatureEntry(name=name, value=None, state=FeatureState.NOT_APPLICABLE, note=note)


# ---------------------------------------------------------------------------
# Feature Extractor
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """Extracts features from analysis stages into the standard 18-dimensional vector."""

    @classmethod
    def extract_features(
        cls,
        doc: IngestedDocument,
        structure: StructuralInspectionResult,
        vba: VBAExtractionResult,
        fused: FusedDetectionResult,
        stomping_sdi: Optional[float] = None,
        stomping_status: str = FeatureState.UNAVAILABLE,
        stomping_note: str = "",
        pcode_tokens: Optional[int] = None,
        pcode_status: str = FeatureState.UNAVAILABLE,
        pcode_note: str = "",
        payload_bytes: Optional[int] = None,
        payload_status: str = FeatureState.UNAVAILABLE,
        payload_note: str = "",
        resolved_api_hashes: Optional[int] = None,
        api_hash_status: str = FeatureState.UNAVAILABLE,
        api_hash_note: str = "",
    ) -> "DocumentFeatureVector":
        """
        Populate all 18 features from pipeline stage results.

        Caller must explicitly pass availability states for advanced features.
        A value of None with status UNAVAILABLE means analysis was not performed.
        A value of 0 with status NOT_DETECTED means analysis ran and found nothing.
        """
        # --- Obfuscation indicator counts (always available from static analysis) ---
        chr_count = sum(1 for f in fused.deduplicated_findings if f.indicator_name == "Chr_Obfuscation")
        strrev_count = sum(1 for f in fused.deduplicated_findings if f.indicator_name == "StrReverse")
        api_count = sum(1 for f in fused.deduplicated_findings if "Win32API_" in f.indicator_name)
        susp_keywords = len([f for f in fused.deduplicated_findings if f.category in ["EXECUTION", "INJECTION", "OBFUSCATION"]])

        # --- Build stomping feature entries ---
        if stomping_sdi is not None:
            f4 = _measured("f4_stomping_discrepancy", round(float(stomping_sdi), 4))
        elif stomping_status == FeatureState.FAILED:
            f4 = _failed("f4_stomping_discrepancy", stomping_note or "P-code analysis failed.")
        elif stomping_status == FeatureState.NOT_APPLICABLE:
            f4 = _not_applicable("f4_stomping_discrepancy", stomping_note or "P-code analysis not applicable.")
        else:
            f4 = _unavailable("f4_stomping_discrepancy", stomping_note or "P-code analysis not performed.")

        # --- Build P-code token count feature ---
        if pcode_tokens is not None:
            f6 = _measured("f6_pcode_token_count", pcode_tokens)
        elif pcode_status == FeatureState.FAILED:
            f6 = _failed("f6_pcode_token_count", pcode_note or "P-code extraction failed.")
        elif pcode_status == FeatureState.NOT_APPLICABLE:
            f6 = _not_applicable("f6_pcode_token_count", pcode_note or "P-code extraction not applicable.")
        else:
            f6 = _unavailable("f6_pcode_token_count", pcode_note or "pcodedmp unavailable or analysis not performed.")

        # --- Build payload bytes feature ---
        if payload_bytes is not None:
            f16 = _measured("f16_extracted_payload_bytes", payload_bytes)
        elif payload_status == FeatureState.FAILED:
            f16 = _failed("f16_extracted_payload_bytes", payload_note or "Payload extraction failed.")
        elif payload_status == FeatureState.NOT_APPLICABLE:
            f16 = _not_applicable("f16_extracted_payload_bytes", payload_note or "Payload extraction not applicable.")
        else:
            f16 = _unavailable("f16_extracted_payload_bytes", payload_note or "Payload extraction not performed.")

        # --- Build resolved API hash count feature ---
        if resolved_api_hashes is not None:
            f17 = _measured("f17_resolved_api_hash_count", resolved_api_hashes)
        elif api_hash_status == FeatureState.FAILED:
            f17 = _failed("f17_resolved_api_hash_count", api_hash_note or "API hash resolution failed.")
        elif api_hash_status == FeatureState.NOT_APPLICABLE:
            f17 = _not_applicable("f17_resolved_api_hash_count", api_hash_note or "API hash resolution not applicable.")
        else:
            f17 = _unavailable("f17_resolved_api_hash_count", api_hash_note or "Shellcode analysis not performed or Capstone unavailable.")

        # Collect unavailable/failed features
        all_features_preview = [f4, f6, f16, f17]
        unavailable = [f.name for f in all_features_preview if f.state == FeatureState.UNAVAILABLE]
        failed = [f.name for f in all_features_preview if f.state == FeatureState.FAILED]
        is_complete = len(unavailable) == 0 and len(failed) == 0

        return DocumentFeatureVector(
            f1_file_size_bytes=_measured("f1_file_size_bytes", doc.file_size_bytes),
            f2_ole_stream_count=_measured("f2_ole_stream_count", structure.stream_count),
            f3_has_vba_project=_measured("f3_has_vba_project", 1 if (structure.has_vba_project or vba.has_macros) else 0),
            f4_stomping_discrepancy=f4,
            f5_source_line_count=_measured("f5_source_line_count", vba.total_line_count),
            f6_pcode_token_count=f6,
            f7_max_stream_entropy=_measured("f7_max_stream_entropy", structure.max_stream_entropy),
            f8_mean_stream_entropy=_measured("f8_mean_stream_entropy", structure.mean_stream_entropy),
            f9_suspicious_keyword_count=_measured("f9_suspicious_keyword_count", susp_keywords),
            f10_obfuscated_chr_count=_measured("f10_obfuscated_chr_count", chr_count),
            f11_strreverse_calls=_measured("f11_strreverse_calls", strrev_count),
            f12_win32_api_declarations=_measured("f12_win32_api_declarations", api_count),
            f13_has_memory_alloc_api=_measured("f13_has_memory_alloc_api", 1 if fused.has_memory_alloc else 0),
            f14_has_memory_copy_api=_measured("f14_has_memory_copy_api", 1 if fused.has_memory_copy else 0),
            f15_has_thread_create_api=_measured("f15_has_thread_create_api", 1 if fused.has_thread_create else 0),
            f16_extracted_payload_bytes=f16,
            f17_resolved_api_hash_count=f17,
            f18_has_c2_network_indicator=_measured("f18_has_c2_network_indicator", 1 if fused.has_c2_indicator else 0),
            analysis_complete=is_complete,
            unavailable_features=unavailable,
            failed_features=failed,
        )

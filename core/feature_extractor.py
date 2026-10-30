"""
18-Dimensional Feature Vector Extractor.
Extracts the standardized [f1..f18] feature representation defined in the project specification
for structured reporting, historical triage comparison, and optional ML evaluation.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, List

from core.ingestion import IngestedDocument
from core.document_inspector import StructuralInspectionResult
from core.vba_extractor import VBAExtractionResult
from core.fusion import FusedDetectionResult


@dataclass
class DocumentFeatureVector:
    """Standardized 18-feature representation."""
    f1_file_size_bytes: int
    f2_ole_stream_count: int
    f3_has_vba_project: int          # 0 or 1
    f4_stomping_discrepancy: float   # SDI index [0.0 - 1.0]
    f5_source_line_count: int
    f6_pcode_token_count: int
    f7_max_stream_entropy: float
    f8_mean_stream_entropy: float
    f9_suspicious_keyword_count: int
    f10_obfuscated_chr_count: int
    f11_strreverse_calls: int
    f12_win32_api_declarations: int
    f13_has_memory_alloc_api: int    # 0 or 1
    f14_has_memory_copy_api: int     # 0 or 1
    f15_has_thread_create_api: int   # 0 or 1
    f16_extracted_payload_bytes: int
    f17_resolved_api_hash_count: int
    f18_has_c2_network_indicator: int # 0 or 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_list(self) -> List[Any]:
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


class FeatureExtractor:
    """Extracts features from analysis stages into the standard 18-dimensional vector."""

    @classmethod
    def extract_features(
        cls,
        doc: IngestedDocument,
        structure: StructuralInspectionResult,
        vba: VBAExtractionResult,
        fused: FusedDetectionResult,
        stomping_sdi: float = 0.0,
        pcode_tokens: int = 0,
        payload_bytes: int = 0,
        resolved_api_hashes: int = 0,
    ) -> DocumentFeatureVector:
        """
        Populate all 18 features from pipeline stage results.
        """
        # Obfuscation indicator counts
        chr_count = sum(1 for f in fused.deduplicated_findings if f.indicator_name == "Chr_Obfuscation")
        strrev_count = sum(1 for f in fused.deduplicated_findings if f.indicator_name == "StrReverse")
        api_count = sum(1 for f in fused.deduplicated_findings if "Win32API_" in f.indicator_name)
        susp_keywords = len([f for f in fused.deduplicated_findings if f.category in ["EXECUTION", "INJECTION", "OBFUSCATION"]])

        return DocumentFeatureVector(
            f1_file_size_bytes=doc.file_size_bytes,
            f2_ole_stream_count=structure.stream_count,
            f3_has_vba_project=1 if (structure.has_vba_project or vba.has_macros) else 0,
            f4_stomping_discrepancy=round(float(stomping_sdi), 4),
            f5_source_line_count=vba.total_line_count,
            f6_pcode_token_count=pcode_tokens,
            f7_max_stream_entropy=structure.max_stream_entropy,
            f8_mean_stream_entropy=structure.mean_stream_entropy,
            f9_suspicious_keyword_count=susp_keywords,
            f10_obfuscated_chr_count=chr_count,
            f11_strreverse_calls=strrev_count,
            f12_win32_api_declarations=api_count,
            f13_has_memory_alloc_api=1 if fused.has_memory_alloc else 0,
            f14_has_memory_copy_api=1 if fused.has_memory_copy else 0,
            f15_has_thread_create_api=1 if fused.has_thread_create else 0,
            f16_extracted_payload_bytes=payload_bytes,
            f17_resolved_api_hash_count=resolved_api_hashes,
            f18_has_c2_network_indicator=1 if fused.has_c2_indicator else 0,
        )

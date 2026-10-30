"""
VBA Extraction Module.
Leverages oletools.olevba to safely extract VBA macros, modules, procedures,
and code lines from both legacy OLE documents and modern OpenXML documents.
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import re
from oletools.olevba import VBA_Parser


@dataclass
class VBAModule:
    """Represents an extracted VBA code module."""
    vba_filename: str
    stream_path: str
    module_name: str
    code: str
    line_count: int
    procedures: List[str] = field(default_factory=list)


@dataclass
class VBAExtractionResult:
    """Summary and contents of extracted VBA project."""
    has_macros: bool
    module_count: int
    total_line_count: int
    modules: List[VBAModule] = field(default_factory=list)
    olevba_analysis: List[Dict[str, Any]] = field(default_factory=list)
    extraction_error: Optional[str] = None


class VBAExtractor:
    """Safely extracts VBA code without executing macros."""

    @staticmethod
    def _extract_procedures(code: str) -> List[str]:
        """Identify Sub and Function procedure declarations in VBA code."""
        procedures = []
        pattern = re.compile(
            r"^\s*(?:Public\s+|Private\s+|Friend\s+)?(?:Static\s+)?(Sub|Function|Property\s+Get|Property\s+Let|Property\s+Set)\s+([a-zA-Z0-9_]+)",
            re.IGNORECASE | re.MULTILINE
        )
        for match in pattern.finditer(code):
            proc_type = match.group(1)
            proc_name = match.group(2)
            procedures.append(f"{proc_type} {proc_name}")
        return procedures

    @classmethod
    def extract_vba(cls, file_path: Path) -> VBAExtractionResult:
        """
        Extract VBA macros from OLE or OpenXML document.
        """
        modules: List[VBAModule] = []
        olevba_findings: List[Dict[str, Any]] = []

        try:
            vbaparser = VBA_Parser(str(file_path))
            has_macros = vbaparser.detect_vba_macros()

            if has_macros:
                # Extract all macro modules
                for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                    if not vba_code:
                        continue
                    code_str = vba_code if isinstance(vba_code, str) else vba_code.decode("utf-8", "ignore")
                    lines = code_str.splitlines()
                    procs = cls._extract_procedures(code_str)

                    # Module name normalization
                    mod_name = vba_filename or Path(stream_path).name or "Module"

                    modules.append(VBAModule(
                        vba_filename=vba_filename or "",
                        stream_path=stream_path or "",
                        module_name=mod_name,
                        code=code_str,
                        line_count=len(lines),
                        procedures=procs
                    ))

                # Run olevba built-in static analysis scanner
                try:
                    results = vbaparser.analyze_macros(show_decoded_strings=True)
                    if results:
                        for kw_type, keyword, description in results:
                            olevba_findings.append({
                                "type": kw_type,
                                "keyword": keyword,
                                "description": description
                            })
                except Exception:
                    pass

            vbaparser.close()

            # Defense-in-depth fallback: if no modules extracted by olevba,
            # inspect OLE / OpenXML streams for raw VBA text
            if not modules:
                import io
                import zipfile
                import olefile
                raw_streams: List[Tuple[str, bytes]] = []

                if zipfile.is_zipfile(str(file_path)):
                    try:
                        with zipfile.ZipFile(str(file_path), "r") as z:
                            for name in z.namelist():
                                if "vba" in name.lower() or name.endswith(".bin"):
                                    data = z.read(name)
                                    if olefile.isOleFile(io.BytesIO(data)):
                                        ole = olefile.OleFileIO(io.BytesIO(data))
                                        for entry in ole.listdir(streams=True, storages=False):
                                            try:
                                                s_bytes = ole.openstream(entry).read()
                                                if s_bytes:
                                                    raw_streams.append(("/".join(entry), s_bytes))
                                            except Exception:
                                                pass
                                        ole.close()
                    except Exception:
                        pass
                elif olefile.isOleFile(str(file_path)):
                    try:
                        ole = olefile.OleFileIO(str(file_path))
                        for entry in ole.listdir(streams=True, storages=False):
                            try:
                                s_bytes = ole.openstream(entry).read()
                                if s_bytes:
                                    raw_streams.append(("/".join(entry), s_bytes))
                            except Exception:
                                pass
                        ole.close()
                    except Exception:
                        pass

                for s_name, s_data in raw_streams:
                    text = s_data.decode("utf-8", "ignore")
                    if any(kw in text.lower() for kw in ["sub ", "function ", "attribute vb_", "end sub", "msgbox"]):
                        procs = cls._extract_procedures(text)
                        lines = text.splitlines()
                        modules.append(VBAModule(
                            vba_filename=s_name,
                            stream_path=s_name,
                            module_name=Path(s_name).name or "Module1",
                            code=text,
                            line_count=len(lines),
                            procedures=procs
                        ))

            total_lines = sum(m.line_count for m in modules)
            return VBAExtractionResult(
                has_macros=len(modules) > 0,
                module_count=len(modules),
                total_line_count=total_lines,
                modules=modules,
                olevba_analysis=olevba_findings
            )

        except Exception as e:
            return VBAExtractionResult(
                has_macros=False,
                module_count=0,
                total_line_count=0,
                modules=[],
                olevba_analysis=[],
                extraction_error=f"Error extracting VBA: {str(e)}"
            )

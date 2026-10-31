"""
Document Structural Inspection Module.
Performs deep structural analysis on OLE Compound File Binary structures
and OpenXML ZIP containers with strict Zip-slip and zip-bomb protections.
"""

import io
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import olefile

from core.hashing import shannon_entropy, calculate_hashes
from core.ingestion import (
    ALL_OLE_EXTENSIONS,
    ALL_OPENXML_EXTENSIONS,
    WORD_EXTENSIONS,
    EXCEL_EXTENSIONS,
    PPT_EXTENSIONS,
)


MAX_ZIP_ENTRIES = 10000
MAX_UNCOMPRESSED_ENTRY_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_TOTAL_UNCOMPRESSED_SIZE = 250 * 1024 * 1024  # 250 MB
MAX_COMPRESSION_RATIO = 100.0  # Zip bomb heuristic


@dataclass
class StreamInfo:
    """Detailed metadata and metrics for an individual stream or container entry."""
    name: str
    size_bytes: int
    entropy: float
    is_vba_related: bool
    is_suspicious_entropy: bool  # entropy > 7.0
    storage_path: str
    sha256: str


@dataclass
class StructuralInspectionResult:
    """Comprehensive structural analysis result."""
    container_type: str  # "OLE" or "OpenXML"
    stream_count: int
    streams: List[StreamInfo] = field(default_factory=list)
    has_vba_project: bool = False
    vba_project_location: Optional[str] = None
    max_stream_entropy: float = 0.0
    mean_stream_entropy: float = 0.0
    suspicious_entries: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    package_type: str = "Unknown"  # "Word", "Excel", "PowerPoint", "Generic"
    external_relationships: List[Dict[str, Any]] = field(default_factory=list)
    embedded_objects: List[Dict[str, Any]] = field(default_factory=list)
    is_corrupt: bool = False
    error: Optional[str] = None


class DocumentInspector:
    """Inspects OLE and OpenXML structures statically and safely."""

    @classmethod
    def inspect_ole_file(cls, file_path_or_bytes: Any) -> StructuralInspectionResult:
        """
        Parse OLE Compound File Binary structure.
        Can accept file path or in-memory bytes (e.g. from extracted vbaProject.bin).
        """
        streams_info: List[StreamInfo] = []
        has_vba = False
        vba_loc = None
        anomalies = []
        pkg_type = "OLE Generic"

        try:
            if isinstance(file_path_or_bytes, bytes):
                ole = olefile.OleFileIO(io.BytesIO(file_path_or_bytes))
            else:
                if not olefile.isOleFile(str(file_path_or_bytes)):
                    return StructuralInspectionResult(
                        container_type="OLE",
                        stream_count=0,
                        is_corrupt=True,
                        error="File is not a valid OLE Compound Document."
                    )
                ole = olefile.OleFileIO(str(file_path_or_bytes))

            with ole:
                if ole.exists("WordDocument"):
                    pkg_type = "Word"
                elif ole.exists("Workbook") or ole.exists("Book"):
                    pkg_type = "Excel"
                elif ole.exists("PowerPoint Document") or ole.exists("Current User"):
                    pkg_type = "PowerPoint"

                # Check extension consistency if file_path is given
                if not isinstance(file_path_or_bytes, bytes):
                    ext = Path(file_path_or_bytes).suffix.lower()
                    if ext in ALL_OPENXML_EXTENSIONS:
                        anomalies.append(f"Extension mismatch: file extension is OpenXML '{ext}' but actual file is an OLE Compound Document (renamed file).")
                    elif pkg_type == "Word" and ext in (EXCEL_EXTENSIONS | PPT_EXTENSIONS):
                        anomalies.append(f"Extension mismatch: file has extension '{ext}' but internal OLE structure contains WordDocument.")
                    elif pkg_type == "Excel" and ext in (WORD_EXTENSIONS | PPT_EXTENSIONS):
                        anomalies.append(f"Extension mismatch: file has extension '{ext}' but internal OLE structure contains Workbook.")
                    elif pkg_type == "PowerPoint" and ext in (WORD_EXTENSIONS | EXCEL_EXTENSIONS):
                        anomalies.append(f"Extension mismatch: file has extension '{ext}' but internal OLE structure contains PowerPoint Document.")

                dir_entries = ole.listdir(streams=True, storages=False)
                for entry in dir_entries:
                    stream_path = "/".join(entry)
                    try:
                        stream_data = ole.openstream(entry).read()
                        stream_size = len(stream_data)
                        ent = shannon_entropy(stream_data)
                        stream_hash = calculate_hashes(stream_data)["sha256"]

                        lower_path = stream_path.lower()
                        is_vba = any(keyword in lower_path for keyword in ["vba", "macros", "_vba_project", "project"])
                        if is_vba:
                            has_vba = True
                            vba_loc = stream_path

                        suspicious_ent = ent > 7.0
                        if suspicious_ent:
                            anomalies.append(f"High-entropy OLE stream ({ent}): {stream_path}")

                        streams_info.append(StreamInfo(
                            name=entry[-1],
                            size_bytes=stream_size,
                            entropy=ent,
                            is_vba_related=is_vba,
                            is_suspicious_entropy=suspicious_ent,
                            storage_path=stream_path,
                            sha256=stream_hash
                        ))
                    except Exception as err:
                        anomalies.append(f"Could not read stream '{stream_path}': {str(err)}")

        except Exception as e:
            return StructuralInspectionResult(
                container_type="OLE",
                stream_count=len(streams_info),
                streams=streams_info,
                is_corrupt=True,
                error=f"Corrupt or malformed OLE structure: {str(e)}"
            )

        stream_count = len(streams_info)
        max_ent = max((s.entropy for s in streams_info), default=0.0)
        mean_ent = round(sum(s.entropy for s in streams_info) / stream_count, 4) if stream_count > 0 else 0.0

        return StructuralInspectionResult(
            container_type="OLE",
            stream_count=stream_count,
            streams=streams_info,
            has_vba_project=has_vba,
            vba_project_location=vba_loc,
            max_stream_entropy=max_ent,
            mean_stream_entropy=mean_ent,
            anomalies=anomalies,
            package_type=pkg_type,
            is_corrupt=False
        )

    @classmethod
    def inspect_openxml_file(cls, file_path: Path) -> StructuralInspectionResult:
        """
        Inspect OpenXML ZIP container with Zip-slip / zip-bomb guards,
        extracting external relationships, embedded objects, and validating package consistency.
        """
        streams_info: List[StreamInfo] = []
        has_vba = False
        vba_loc = None
        suspicious_entries = []
        anomalies = []
        vba_bin_bytes: Optional[bytes] = None
        external_relationships: List[Dict[str, Any]] = []
        embedded_objects: List[Dict[str, Any]] = []
        pkg_type = "OpenXML Package (Generic)"

        dangerous_extensions = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl", ".scr"}

        try:
            with zipfile.ZipFile(str(file_path), "r") as z:
                infolist = z.infolist()
                names_lower = [info.filename.lower() for info in infolist]

                # Determine package type
                if any(n.startswith("word/") for n in names_lower):
                    pkg_type = "Word"
                elif any(n.startswith("xl/") for n in names_lower):
                    pkg_type = "Excel"
                elif any(n.startswith("ppt/") for n in names_lower):
                    pkg_type = "PowerPoint"

                # Check extension consistency
                ext = Path(file_path).suffix.lower()
                if ext in ALL_OLE_EXTENSIONS:
                    anomalies.append(f"Extension mismatch: file extension is legacy OLE '{ext}' but internal package is an OpenXML ZIP container (renamed file).")
                elif pkg_type == "Word" and ext in (EXCEL_EXTENSIONS | PPT_EXTENSIONS):
                    anomalies.append(f"Extension mismatch: file extension is '{ext}' but internal package structure corresponds to Microsoft Word.")
                elif pkg_type == "Excel" and ext in (WORD_EXTENSIONS | PPT_EXTENSIONS):
                    anomalies.append(f"Extension mismatch: file extension is '{ext}' but internal package structure corresponds to Microsoft Excel.")
                elif pkg_type == "PowerPoint" and ext in (WORD_EXTENSIONS | EXCEL_EXTENSIONS):
                    anomalies.append(f"Extension mismatch: file extension is '{ext}' but internal package structure corresponds to Microsoft PowerPoint.")

                if len(infolist) > MAX_ZIP_ENTRIES:
                    return StructuralInspectionResult(
                        container_type="OpenXML",
                        stream_count=len(infolist),
                        package_type=pkg_type,
                        is_corrupt=True,
                        error=f"Zip entry count ({len(infolist)}) exceeds safety threshold ({MAX_ZIP_ENTRIES}). Potential DoS."
                    )

                total_uncompressed = 0
                for info in infolist:
                    filename = info.filename

                    # 1. Zip slip / path traversal checks
                    if filename.startswith("/") or filename.startswith("\\") or ".." in filename.replace("\\", "/").split("/"):
                        anomalies.append(f"Zip slip / directory traversal entry detected: {filename}")
                        suspicious_entries.append(filename)

                    # 2. Decompression checks
                    if info.file_size > MAX_UNCOMPRESSED_ENTRY_SIZE:
                        return StructuralInspectionResult(
                            container_type="OpenXML",
                            stream_count=len(infolist),
                            package_type=pkg_type,
                            is_corrupt=True,
                            error=f"Zip entry '{filename}' size ({info.file_size} bytes) exceeds limit ({MAX_UNCOMPRESSED_ENTRY_SIZE})."
                        )

                    total_uncompressed += info.file_size
                    if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_SIZE:
                        return StructuralInspectionResult(
                            container_type="OpenXML",
                            stream_count=len(infolist),
                            package_type=pkg_type,
                            is_corrupt=True,
                            error=f"Total uncompressed ZIP size exceeds limit ({MAX_TOTAL_UNCOMPRESSED_SIZE}). Potential Zip Bomb."
                        )

                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > MAX_COMPRESSION_RATIO:
                            anomalies.append(f"Abnormally high compression ratio ({ratio:.1f}:1) for entry: {filename}")

                    # Check for dangerous embedded executables or scripts
                    entry_ext = Path(filename).suffix.lower()
                    if entry_ext in dangerous_extensions:
                        suspicious_entries.append(filename)
                        anomalies.append(f"Suspicious executable or script embedded in container: {filename}")

                    # Read entry safely
                    try:
                        content = z.read(info)
                        ent = shannon_entropy(content)
                        h = calculate_hashes(content)["sha256"]

                        # Check if VBA project
                        is_vba = "vbaProject.bin" in filename or "vba" in filename.lower()
                        if "vbaProject.bin" in filename:
                            has_vba = True
                            vba_loc = filename
                            vba_bin_bytes = content

                        # Inspect relationships (.rels)
                        if filename.lower().endswith(".rels"):
                            try:
                                root = ET.fromstring(content)
                                for elem in root.iter():
                                    if elem.tag.endswith("Relationship"):
                                        target = elem.attrib.get("Target", "")
                                        target_mode = elem.attrib.get("TargetMode", "")
                                        rel_type = elem.attrib.get("Type", "")
                                        is_external = target_mode.lower() == "external" or any(target.lower().startswith(p) for p in ["http://", "https://", "ftp://", "\\\\", "file://", "ms-msdt:", "search-ms:", "mhtml:"])
                                        if is_external:
                                            is_template = ("attachedtemplate" in rel_type.lower()) or any(target.lower().endswith(x) for x in [".dot", ".dotm", ".docm", ".dotx"])
                                            is_protocol = any(target.lower().startswith(p) for p in ["ms-msdt:", "search-ms:", "file:", "\\\\", "mhtml:"])
                                            if is_template:
                                                anomalies.append(f"Remote template injection detected in '{filename}': target='{target}'")
                                            elif is_protocol:
                                                anomalies.append(f"Suspicious external protocol handler detected in '{filename}': target='{target}'")
                                            else:
                                                anomalies.append(f"External relationship detected in '{filename}': target='{target}'")

                                            external_relationships.append({
                                                "source_part": filename,
                                                "target": target,
                                                "type": rel_type,
                                                "target_mode": target_mode,
                                                "is_template_injection": is_template,
                                                "is_suspicious_protocol": is_protocol,
                                                "is_suspicious": is_template or is_protocol or target_mode.lower() == "external",
                                            })
                            except Exception:
                                pass

                        # Inspect embedded objects / OLE objects / binary packages
                        lower_fn = filename.lower()
                        is_embedded = (
                            "embeddings/" in lower_fn or
                            (lower_fn.endswith(".bin") and "vbaproject.bin" not in lower_fn) or
                            lower_fn.endswith(".ole") or
                            "oleobject" in lower_fn
                        )
                        if is_embedded:
                            is_ole = content.startswith(b"\xD0\xCF\x11\xE0")
                            embedded_objects.append({
                                "storage_path": filename,
                                "size_bytes": info.file_size,
                                "entropy": ent,
                                "sha256": h,
                                "is_ole": is_ole
                            })
                            anomalies.append(f"Embedded object detected in package ({'OLE Compound Document' if is_ole else 'Binary Object'}): {filename} ({info.file_size} bytes)")
                            if is_ole:
                                try:
                                    inner_ole = cls.inspect_ole_file(content)
                                    for s in inner_ole.streams:
                                        if "ole10native" in s.name.lower():
                                            anomalies.append(f"Embedded OLE object contains Ole10Native package stream: {filename}!{s.storage_path}")
                                except Exception:
                                    pass

                        susp_ent = ent > 7.0
                        if susp_ent:
                            anomalies.append(f"High-entropy OpenXML stream ({ent}): {filename}")

                        streams_info.append(StreamInfo(
                            name=Path(filename).name,
                            size_bytes=info.file_size,
                            entropy=ent,
                            is_vba_related=is_vba,
                            is_suspicious_entropy=susp_ent,
                            storage_path=filename,
                            sha256=h
                        ))
                    except Exception as re:
                        anomalies.append(f"Failed to read ZIP entry '{filename}': {str(re)}")

        except zipfile.BadZipFile as bz:
            return StructuralInspectionResult(
                container_type="OpenXML",
                stream_count=0,
                package_type=pkg_type,
                is_corrupt=True,
                error=f"Malformed or corrupted OpenXML ZIP archive: {str(bz)}"
            )
        except Exception as e:
            return StructuralInspectionResult(
                container_type="OpenXML",
                stream_count=0,
                package_type=pkg_type,
                is_corrupt=True,
                error=f"Unexpected error during OpenXML inspection: {str(e)}"
            )

        # If vbaProject.bin was found inside OpenXML, inspect it as an inner OLE compound document
        if vba_bin_bytes:
            try:
                inner_ole = cls.inspect_ole_file(vba_bin_bytes)
                if not inner_ole.is_corrupt:
                    for s in inner_ole.streams:
                        streams_info.append(StreamInfo(
                            name=f"vbaProject.bin:{s.name}",
                            size_bytes=s.size_bytes,
                            entropy=s.entropy,
                            is_vba_related=True,
                            is_suspicious_entropy=s.is_suspicious_entropy,
                            storage_path=f"vbaProject.bin!{s.storage_path}",
                            sha256=s.sha256
                        ))
            except Exception as e:
                anomalies.append(f"Could not inspect inner vbaProject.bin as OLE: {str(e)}")

        stream_count = len(streams_info)
        max_ent = max((s.entropy for s in streams_info), default=0.0)
        mean_ent = round(sum(s.entropy for s in streams_info) / stream_count, 4) if stream_count > 0 else 0.0

        return StructuralInspectionResult(
            container_type="OpenXML",
            stream_count=stream_count,
            streams=streams_info,
            has_vba_project=has_vba,
            vba_project_location=vba_loc,
            max_stream_entropy=max_ent,
            mean_stream_entropy=mean_ent,
            suspicious_entries=suspicious_entries,
            anomalies=anomalies,
            package_type=pkg_type,
            external_relationships=external_relationships,
            embedded_objects=embedded_objects,
            is_corrupt=False
        )

    @classmethod
    def inspect(cls, file_path: Path, detected_format: str) -> StructuralInspectionResult:
        """Inspect file according to detected format."""
        if detected_format == "OLE":
            return cls.inspect_ole_file(file_path)
        elif detected_format == "OpenXML":
            return cls.inspect_openxml_file(file_path)
        else:
            return StructuralInspectionResult(
                container_type="UNSUPPORTED",
                stream_count=0,
                is_corrupt=True,
                error=f"Cannot inspect unsupported format: {detected_format}"
            )

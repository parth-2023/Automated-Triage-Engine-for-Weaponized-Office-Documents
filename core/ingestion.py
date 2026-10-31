"""
File Ingestion and Validation Module.
Handles safe reception, path sanitization, magic signature verification,
file-size enforcement, and secure temporary storage for Office documents.
"""

import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple
import olefile

from core.hashing import calculate_hashes, shannon_entropy


# Standard magic signatures
OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
ZIP_MAGIC = b"\x50\x4B\x03\x04"

# Supported Office Format Extensions
WORD_OLE_EXTENSIONS = {".doc", ".dot"}
WORD_OPENXML_EXTENSIONS = {".docx", ".docm", ".dotx", ".dotm"}
WORD_EXTENSIONS = WORD_OLE_EXTENSIONS | WORD_OPENXML_EXTENSIONS

EXCEL_OLE_EXTENSIONS = {".xls", ".xlt"}
EXCEL_OPENXML_EXTENSIONS = {".xlsx", ".xlsm", ".xltx", ".xltm"}
EXCEL_EXTENSIONS = EXCEL_OLE_EXTENSIONS | EXCEL_OPENXML_EXTENSIONS

PPT_OLE_EXTENSIONS = {".ppt"}
PPT_OPENXML_EXTENSIONS = {".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"}
PPT_EXTENSIONS = PPT_OLE_EXTENSIONS | PPT_OPENXML_EXTENSIONS

ALL_OLE_EXTENSIONS = WORD_OLE_EXTENSIONS | EXCEL_OLE_EXTENSIONS | PPT_OLE_EXTENSIONS
ALL_OPENXML_EXTENSIONS = WORD_OPENXML_EXTENSIONS | EXCEL_OPENXML_EXTENSIONS | PPT_OPENXML_EXTENSIONS
SUPPORTED_EXTENSIONS = ALL_OLE_EXTENSIONS | ALL_OPENXML_EXTENSIONS

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


class IngestionError(Exception):
    """Base exception for file ingestion failures."""
    pass


@dataclass
class IngestedDocument:
    """Represents a validated and ingested document."""
    original_filename: str
    safe_filename: str
    file_path: Path
    file_size_bytes: int
    hashes: Dict[str, str]
    file_entropy: float
    detected_format: str  # "OLE" or "OpenXML" or "UNSUPPORTED"
    extension: str
    package_type: str = "Unknown"  # "Word", "Excel", "PowerPoint", "Generic"
    is_valid: bool = True
    error_message: Optional[str] = None
    validation_notes: List[str] = field(default_factory=list)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and shell injection.
    Strips directory separators and non-whitelisted characters.
    """
    base_name = os.path.basename(filename.strip().replace("\\", "/"))
    # Replace any character that is not alphanumeric, dot, underscore, or dash
    clean_name = re.sub(r"[^\w\.-]", "_", base_name)
    if not clean_name or clean_name.startswith("."):
        clean_name = f"document_{clean_name}"
    return clean_name[:255]


def verify_file_signature(data_header: bytes) -> str:
    """
    Inspect the file header bytes to identify format family.
    Returns 'OLE', 'OpenXML', or 'UNKNOWN'.
    """
    if len(data_header) < 4:
        return "TOO_SHORT"
    if data_header.startswith(OLE_MAGIC[:4]):
        return "OLE"
    if data_header.startswith(ZIP_MAGIC):
        return "OpenXML"
    return "UNKNOWN"


def detect_package_type_and_check_consistency(file_path: Path, detected_format: str, ext: str) -> Tuple[str, List[str]]:
    """
    Inspect internal package structure to identify application (Word, Excel, PowerPoint)
    and validate consistency against the declared file extension.
    Never executes any macro, payload, or embedded code.
    """
    notes: List[str] = []
    pkg_type = "Unknown"

    if detected_format == "OpenXML":
        try:
            with zipfile.ZipFile(str(file_path), "r") as z:
                names = [n.lower() for n in z.namelist()]
                # Check for Word parts
                is_word = any(n.startswith("word/") for n in names)
                # Check for Excel parts
                is_excel = any(n.startswith("xl/") for n in names)
                # Check for PowerPoint parts
                is_ppt = any(n.startswith("ppt/") for n in names)

                # Secondary content-type inspection if ambiguous
                if not (is_word or is_excel or is_ppt) and "[content_types].xml" in names:
                    try:
                        ct_data = z.read("[Content_Types].xml")[:16384].decode("utf-8", "ignore").lower()
                        if "wordprocessingml" in ct_data or "application/vnd.ms-word" in ct_data:
                            is_word = True
                        elif "spreadsheetml" in ct_data or "application/vnd.ms-excel" in ct_data:
                            is_excel = True
                        elif "presentationml" in ct_data or "application/vnd.ms-powerpoint" in ct_data:
                            is_ppt = True
                    except Exception:
                        pass

                if is_word:
                    pkg_type = "Word"
                elif is_excel:
                    pkg_type = "Excel"
                elif is_ppt:
                    pkg_type = "PowerPoint"
                else:
                    pkg_type = "OpenXML Package (Generic)"

                notes.append(f"Identified OpenXML package structure: {pkg_type}.")

                # Consistency checks
                if ext in ALL_OLE_EXTENSIONS:
                    notes.append(f"Extension mismatch: file has legacy OLE extension '{ext}' but internal container is an OpenXML ZIP package (renamed file).")
                elif pkg_type == "Word" and ext in (EXCEL_EXTENSIONS | PPT_EXTENSIONS):
                    notes.append(f"Package mismatch: file has extension '{ext}' but internal package corresponds to Microsoft Word.")
                elif pkg_type == "Excel" and ext in (WORD_EXTENSIONS | PPT_EXTENSIONS):
                    notes.append(f"Package mismatch: file has extension '{ext}' but internal package corresponds to Microsoft Excel.")
                elif pkg_type == "PowerPoint" and ext in (WORD_EXTENSIONS | EXCEL_EXTENSIONS):
                    notes.append(f"Package mismatch: file has extension '{ext}' but internal package corresponds to Microsoft PowerPoint.")

        except Exception as e:
            pkg_type = "OpenXML (Corrupt/Malformed)"
            notes.append(f"OpenXML package verification note: could not read internal ZIP index ({str(e)}).")

    elif detected_format == "OLE":
        try:
            if olefile.isOleFile(str(file_path)):
                with olefile.OleFileIO(str(file_path)) as ole:
                    # Check for Word
                    if ole.exists("WordDocument"):
                        pkg_type = "Word"
                    # Check for Excel
                    elif ole.exists("Workbook") or ole.exists("Book"):
                        pkg_type = "Excel"
                    # Check for PowerPoint
                    elif ole.exists("PowerPoint Document") or ole.exists("Current User"):
                        pkg_type = "PowerPoint"
                    else:
                        pkg_type = "OLE Container (Generic)"

                    notes.append(f"Identified OLE stream structure: {pkg_type}.")

                    # Consistency checks
                    if ext in ALL_OPENXML_EXTENSIONS:
                        notes.append(f"Extension mismatch: file has OpenXML extension '{ext}' but file signature is a legacy OLE Compound Document (renamed file).")
                    elif pkg_type == "Word" and ext in (EXCEL_EXTENSIONS | PPT_EXTENSIONS):
                        notes.append(f"Package mismatch: file has extension '{ext}' but internal OLE structure contains WordDocument.")
                    elif pkg_type == "Excel" and ext in (WORD_EXTENSIONS | PPT_EXTENSIONS):
                        notes.append(f"Package mismatch: file has extension '{ext}' but internal OLE structure contains Excel Workbook.")
                    elif pkg_type == "PowerPoint" and ext in (WORD_EXTENSIONS | EXCEL_EXTENSIONS):
                        notes.append(f"Package mismatch: file has extension '{ext}' but internal OLE structure contains PowerPoint Document.")
            else:
                pkg_type = "OLE (Malformed)"
                notes.append("OLE verification note: header matches magic bytes but OLE structure is malformed.")
        except Exception as e:
            pkg_type = "OLE (Corrupt/Malformed)"
            notes.append(f"OLE structure verification note: {str(e)}.")

    return pkg_type, notes


class IngestionManager:
    """
    Manages safe ingestion of uploaded documents within secure temporary workspaces.
    """
    def __init__(self, max_file_size: int = DEFAULT_MAX_FILE_SIZE):
        self.max_file_size = max_file_size
        self._temp_dirs: List[tempfile.TemporaryDirectory] = []

    def create_safe_workspace(self) -> Path:
        """Create a secure isolated temporary directory."""
        temp_dir = tempfile.TemporaryDirectory(prefix="mal_triage_")
        self._temp_dirs.append(temp_dir)
        return Path(temp_dir.name)

    def ingest_file(self, input_path_or_bytes: Any, original_name: Optional[str] = None) -> IngestedDocument:
        """
        Ingest, validate, and store a document safely.
        """
        workspace = self.create_safe_workspace()

        # Handle file path vs raw bytes
        if isinstance(input_path_or_bytes, (str, Path)):
            source_path = Path(input_path_or_bytes)
            if not source_path.exists():
                raise IngestionError(f"Input file does not exist: {source_path}")
            file_name = original_name or source_path.name
            safe_name = sanitize_filename(file_name)
            target_path = workspace / safe_name
            shutil.copyfile(source_path, target_path)
            file_size = target_path.stat().st_size
            with open(target_path, "rb") as f:
                header = f.read(16)
        elif isinstance(input_path_or_bytes, bytes):
            file_name = original_name or "uploaded_document.bin"
            safe_name = sanitize_filename(file_name)
            target_path = workspace / safe_name
            file_size = len(input_path_or_bytes)
            with open(target_path, "wb") as f:
                f.write(input_path_or_bytes)
            header = input_path_or_bytes[:16]
        else:
            raise IngestionError(f"Unsupported input type: {type(input_path_or_bytes).__name__}")

        # Check empty file
        if file_size == 0:
            return IngestedDocument(
                original_filename=file_name,
                safe_filename=safe_name,
                file_path=target_path,
                file_size_bytes=0,
                hashes={"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha1": "", "md5": ""},
                file_entropy=0.0,
                detected_format="EMPTY",
                extension=Path(safe_name).suffix.lower(),
                is_valid=False,
                error_message="File is empty (0 bytes).",
                validation_notes=["Rejected: zero-byte input."]
            )

        # Check file size limit
        if file_size > self.max_file_size:
            return IngestedDocument(
                original_filename=file_name,
                safe_filename=safe_name,
                file_path=target_path,
                file_size_bytes=file_size,
                hashes=calculate_hashes(target_path),
                file_entropy=0.0,
                detected_format="OVERSIZED",
                extension=Path(safe_name).suffix.lower(),
                is_valid=False,
                error_message=f"File size ({file_size} bytes) exceeds limit ({self.max_file_size} bytes).",
                validation_notes=["Rejected: file exceeds configured size boundary."]
            )

        # Calculate hashes and whole-file entropy
        hashes = calculate_hashes(target_path)
        with open(target_path, "rb") as f:
            full_data = f.read()
        file_ent = shannon_entropy(full_data)

        # Extension and signature verification
        ext = Path(safe_name).suffix.lower()
        sig_format = verify_file_signature(header)
        notes = []

        if ext not in SUPPORTED_EXTENSIONS:
            notes.append(f"Extension '{ext}' is not among supported Office extensions.")

        if sig_format == "OLE":
            detected = "OLE"
            notes.append("Verified OLE Compound File Binary format.")
        elif sig_format == "OpenXML":
            detected = "OpenXML"
            notes.append("Verified OpenXML ZIP container format.")
        else:
            detected = "UNSUPPORTED"
            return IngestedDocument(
                original_filename=file_name,
                safe_filename=safe_name,
                file_path=target_path,
                file_size_bytes=file_size,
                hashes=hashes,
                file_entropy=file_ent,
                detected_format=detected,
                extension=ext,
                package_type="Unsupported",
                is_valid=False,
                error_message=f"Unsupported file signature: header {header[:8].hex()}",
                validation_notes=notes + ["Rejected: Magic signature does not match OLE or OpenXML container."]
            )

        pkg_type, pkg_notes = detect_package_type_and_check_consistency(target_path, detected, ext)
        notes.extend(pkg_notes)

        return IngestedDocument(
            original_filename=file_name,
            safe_filename=safe_name,
            file_path=target_path,
            file_size_bytes=file_size,
            hashes=hashes,
            file_entropy=file_ent,
            detected_format=detected,
            extension=ext,
            package_type=pkg_type,
            is_valid=True,
            error_message=None,
            validation_notes=notes
        )

    def cleanup(self):
        """Clean up all temporary directories."""
        for temp_dir in self._temp_dirs:
            try:
                temp_dir.cleanup()
            except Exception:
                pass
        self._temp_dirs.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

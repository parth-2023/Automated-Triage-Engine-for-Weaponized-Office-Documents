"""
File Ingestion and Validation Module.
Handles safe reception, path sanitization, magic signature verification,
file-size enforcement, and secure temporary storage for Office documents.
"""

import os
import re
import shutil
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from core.hashing import calculate_hashes, shannon_entropy


# Standard magic signatures
OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
ZIP_MAGIC = b"\x50\x4B\x03\x04"

SUPPORTED_EXTENSIONS = {".doc", ".docm", ".xls", ".xlsm"}
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
    if len(data_header) < 8:
        return "TOO_SHORT"
    if data_header.startswith(OLE_MAGIC):
        return "OLE"
    if data_header.startswith(ZIP_MAGIC):
        return "OpenXML"
    return "UNKNOWN"


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
            notes.append(f"Extension '{ext}' is not among primary targets (.doc, .docm, .xls, .xlsm).")

        if sig_format == "OLE":
            detected = "OLE"
            notes.append("Verified OLE Compound File Binary format (DOC/XLS).")
        elif sig_format == "OpenXML":
            detected = "OpenXML"
            notes.append("Verified OpenXML ZIP container format (DOCM/XLSM).")
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
                is_valid=False,
                error_message=f"Unsupported file signature: header {header[:8].hex()}",
                validation_notes=notes + ["Rejected: Magic signature does not match OLE or OpenXML container."]
            )

        return IngestedDocument(
            original_filename=file_name,
            safe_filename=safe_name,
            file_path=target_path,
            file_size_bytes=file_size,
            hashes=hashes,
            file_entropy=file_ent,
            detected_format=detected,
            extension=ext,
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

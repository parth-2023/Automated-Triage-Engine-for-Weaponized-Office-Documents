"""
Metadata Extraction Module.
Safely extracts document properties from OLE SummaryInformation streams
and OpenXML docProps/core.xml and docProps/app.xml files.
"""

import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, Optional
import olefile


class MetadataExtractor:
    """Extracts metadata from OLE and OpenXML files without running any executable code."""

    @staticmethod
    def extract_ole_metadata(file_path: Path) -> Dict[str, Any]:
        """Extract metadata from OLE Compound Document."""
        metadata = {
            "format": "OLE",
            "author": None,
            "title": None,
            "subject": None,
            "comments": None,
            "last_saved_by": None,
            "create_time": None,
            "last_saved_time": None,
            "creating_application": None,
            "revision_number": None,
            "total_edit_time": None,
        }

        try:
            if not olefile.isOleFile(str(file_path)):
                return metadata

            with olefile.OleFileIO(str(file_path)) as ole:
                meta = ole.get_metadata()
                if meta:
                    metadata["author"] = meta.author.decode("utf-8", "ignore") if isinstance(meta.author, bytes) else str(meta.author or "")
                    metadata["title"] = meta.title.decode("utf-8", "ignore") if isinstance(meta.title, bytes) else str(meta.title or "")
                    metadata["subject"] = meta.subject.decode("utf-8", "ignore") if isinstance(meta.subject, bytes) else str(meta.subject or "")
                    metadata["comments"] = meta.comments.decode("utf-8", "ignore") if isinstance(meta.comments, bytes) else str(meta.comments or "")
                    metadata["last_saved_by"] = meta.last_saved_by.decode("utf-8", "ignore") if isinstance(meta.last_saved_by, bytes) else str(meta.last_saved_by or "")
                    metadata["create_time"] = str(meta.create_time) if meta.create_time else None
                    metadata["last_saved_time"] = str(meta.last_saved_time) if meta.last_saved_time else None
                    metadata["creating_application"] = meta.creating_application.decode("utf-8", "ignore") if isinstance(meta.creating_application, bytes) else str(meta.creating_application or "")
                    metadata["revision_number"] = str(meta.revision_number) if meta.revision_number else None
                    metadata["total_edit_time"] = str(meta.total_edit_time) if meta.total_edit_time else None
        except Exception as e:
            metadata["error"] = f"OLE metadata extraction error: {str(e)}"

        return metadata

    @staticmethod
    def extract_openxml_metadata(file_path: Path) -> Dict[str, Any]:
        """Extract metadata from OpenXML docProps/core.xml and docProps/app.xml."""
        metadata = {
            "format": "OpenXML",
            "author": None,
            "title": None,
            "subject": None,
            "description": None,
            "last_saved_by": None,
            "create_time": None,
            "last_saved_time": None,
            "creating_application": None,
            "app_version": None,
            "revision_number": None,
        }

        try:
            with zipfile.ZipFile(str(file_path), "r") as z:
                # 1. Parse core.xml
                if "docProps/core.xml" in z.namelist():
                    core_xml = z.read("docProps/core.xml")
                    root = ET.fromstring(core_xml)
                    # Namespaces commonly used
                    ns = {
                        "dc": "http://purl.org/dc/elements/1.1/",
                        "dcterms": "http://purl.org/dc/terms/",
                        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                    }
                    creator = root.find("dc:creator", ns)
                    if creator is not None and creator.text:
                        metadata["author"] = creator.text

                    title = root.find("dc:title", ns)
                    if title is not None and title.text:
                        metadata["title"] = title.text

                    subject = root.find("dc:subject", ns)
                    if subject is not None and subject.text:
                        metadata["subject"] = subject.text

                    desc = root.find("dc:description", ns)
                    if desc is not None and desc.text:
                        metadata["description"] = desc.text

                    last_mod = root.find("cp:lastModifiedBy", ns)
                    if last_mod is not None and last_mod.text:
                        metadata["last_saved_by"] = last_mod.text

                    created = root.find("dcterms:created", ns)
                    if created is not None and created.text:
                        metadata["create_time"] = created.text

                    modified = root.find("dcterms:modified", ns)
                    if modified is not None and modified.text:
                        metadata["last_saved_time"] = modified.text

                    revision = root.find("cp:revision", ns)
                    if revision is not None and revision.text:
                        metadata["revision_number"] = revision.text

                # 2. Parse app.xml
                if "docProps/app.xml" in z.namelist():
                    app_xml = z.read("docProps/app.xml")
                    root_app = ET.fromstring(app_xml)
                    ns_app = {"ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}
                    app_elem = root_app.find("ep:Application", ns_app)
                    if app_elem is not None and app_elem.text:
                        metadata["creating_application"] = app_elem.text
                    app_ver = root_app.find("ep:AppVersion", ns_app)
                    if app_ver is not None and app_ver.text:
                        metadata["app_version"] = app_ver.text

        except Exception as e:
            metadata["error"] = f"OpenXML metadata extraction error: {str(e)}"

        return metadata

    @classmethod
    def extract(cls, file_path: Path, detected_format: str) -> Dict[str, Any]:
        """Dispatcher based on detected format."""
        if detected_format == "OLE":
            return cls.extract_ole_metadata(file_path)
        elif detected_format == "OpenXML":
            return cls.extract_openxml_metadata(file_path)
        return {"format": detected_format, "error": "Unsupported format for metadata extraction"}

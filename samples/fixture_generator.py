"""
Harmless Test Fixture Generator.
Creates programmatically generated, strictly benign synthetic documents
for testing ingestion, structural inspection, and macro extraction.
No live malware is ever created or downloaded.
"""

import io
import os
import zipfile
from pathlib import Path
from typing import Dict
import olefile


SAMPLE_DIR = Path(__file__).resolve().parent / "harmless_test_fixtures"


def create_minimal_openxml(target_path: Path, vba_code: str = None, is_excel: bool = False) -> Path:
    """
    Create a valid minimal OpenXML document (.docm or .xlsm).
    If vba_code is provided, embeds a minimal vbaProject.bin with harmless macro.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)

    content_types_word = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
    <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
    <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

    core_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">
    <dc:title>Benign Test Document</dc:title>
    <dc:creator>Security Analyst</dc:creator>
    <cp:revision>1</cp:revision>
    <dcterms:created xsi:type="dcterms:W3CDTF" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">2026-01-01T00:00:00Z</dcterms:created>
</cp:coreProperties>"""

    app_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
    <Application>Microsoft Office Word</Application>
    <AppVersion>16.0000</AppVersion>
</Properties>"""

    doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body><w:p><w:r><w:t>Harmless Test Sample</w:t></w:r></w:p></w:body>
</w:document>"""

    with zipfile.ZipFile(target_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types_word)
        z.writestr("docProps/core.xml", core_xml)
        z.writestr("docProps/app.xml", app_xml)
        z.writestr("word/document.xml", doc_xml)

        if vba_code:
            # Create a synthetic vbaProject.bin with VBA-like stream
            vba_bin = create_minimal_vba_bin(vba_code)
            z.writestr("word/vbaProject.bin", vba_bin)

    return target_path


def create_minimal_vba_bin(vba_source: str) -> bytes:
    """
    Generate minimal OLE compound file representing vbaProject.bin with VBA streams.
    """
    buf = io.BytesIO()
    # Construct an OLE file with VBA project streams
    # Minimum OLE header: 512 bytes header
    # To ensure olefile and olevba parse it, we use olefile or standard layout
    # In OLE, header magic is D0 CF 11 E0 A1 B1 1A E1
    ole = olefile.OleFileIO()
    # We can create a valid OLE file using standard OLE blocks
    # An OLE file has sectors of 512 bytes
    header = bytearray(512)
    header[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    header[28:30] = b"\xFE\xFF" # Little endian
    header[30:32] = b"\x09\x00" # Sector size 2^9 = 512
    header[32:34] = b"\x06\x00" # Mini sector size 2^6 = 64
    header[44:48] = b"\x01\x00\x00\x00" # 1 SAT sector
    header[48:52] = b"\x01\x00\x00\x00" # Dir sector at sec 1
    header[60:64] = b"\xFE\xFF\xFF\xFF" # Mini FAT end
    header[68:72] = b"\xFE\xFF\xFF\xFF" # Mini stream end
    header[76:80] = b"\x00\x00\x00\x00" # First SAT sector at sector 0
    # Fill remainder of header MSAT array (entries 0..108)
    for i in range(109):
        offset = 76 + i * 4
        if i == 0:
            header[offset:offset+4] = b"\x00\x00\x00\x00"
        else:
            header[offset:offset+4] = b"\xFE\xFF\xFF\xFF" # End of chain

    # Sector 0: SAT (Sector Allocation Table)
    sat = bytearray(512)
    # Entry 0: SAT itself -> FAT_SECT (0xFFFFFFFD)
    sat[0:4] = b"\xFD\xFF\xFF\xFF"
    # Entry 1: Directory sector -> ENDOFCHAIN (0xFFFFFFFE)
    sat[4:8] = b"\xFE\xFF\xFF\xFF"
    # Entry 2: Stream 1 (VBA code) -> ENDOFCHAIN
    sat[8:12] = b"\xFE\xFF\xFF\xFF"
    # Mark remaining SAT entries as unallocated (0xFFFFFFFF)
    for i in range(3, 128):
        sat[i*4:(i+1)*4] = b"\xFF\xFF\xFF\xFF"

    # Sector 1: Directory sector (4 entries of 128 bytes each)
    dir_sec = bytearray(512)
    # Entry 0: Root Entry (type 5)
    root_name = "Root Entry\x00".encode("utf-16le")
    dir_sec[0:len(root_name)] = root_name
    dir_sec[64:66] = len(root_name).to_bytes(2, "little")
    dir_sec[66] = 5 # Root storage
    dir_sec[67] = 1 # Black
    dir_sec[68:72] = b"\xFF\xFF\xFF\xFF" # Left sibling
    dir_sec[72:76] = b"\xFF\xFF\xFF\xFF" # Right sibling
    dir_sec[76:80] = b"\x01\x00\x00\x00" # Child = entry 1 (Dir stream)
    dir_sec[116:120] = b"\xFE\xFF\xFF\xFF" # Starting sec
    dir_sec[120:124] = b"\x00\x00\x00\x00" # Size

    # Entry 1: VBA Stream (type 2 = stream)
    stream_name = "VBA_Code\x00".encode("utf-16le")
    dir_sec[128:128+len(stream_name)] = stream_name
    dir_sec[192:194] = len(stream_name).to_bytes(2, "little")
    dir_sec[194] = 2 # User stream
    dir_sec[195] = 1 # Black
    dir_sec[196:200] = b"\xFF\xFF\xFF\xFF" # Left
    dir_sec[200:204] = b"\xFF\xFF\xFF\xFF" # Right
    dir_sec[204:208] = b"\xFF\xFF\xFF\xFF" # Child
    dir_sec[244:248] = b"\x02\x00\x00\x00" # Sector 2
    code_bytes = vba_source.encode("utf-8")
    dir_sec[248:252] = len(code_bytes).to_bytes(4, "little")

    # Sector 2: Stream content
    stream_sec = bytearray(512)
    stream_sec[0:len(code_bytes)] = code_bytes

    return bytes(header) + bytes(sat) + bytes(dir_sec) + bytes(stream_sec)


def create_minimal_ole(target_path: Path, stream_data: bytes = b"Benign OLE Content", stream_name: str = "SummaryInformation") -> Path:
    """
    Create a valid minimal OLE document (.doc or .xls).
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    header = bytearray(512)
    header[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    header[28:30] = b"\xFE\xFF"
    header[30:32] = b"\x09\x00"
    header[32:34] = b"\x06\x00"
    header[44:48] = b"\x01\x00\x00\x00"
    header[48:52] = b"\x01\x00\x00\x00"
    header[60:64] = b"\xFE\xFF\xFF\xFF"
    header[68:72] = b"\xFE\xFF\xFF\xFF"
    header[76:80] = b"\x00\x00\x00\x00"
    for i in range(1, 109):
        header[76 + i * 4 : 80 + i * 4] = b"\xFE\xFF\xFF\xFF"

    sat = bytearray(512)
    sat[0:4] = b"\xFD\xFF\xFF\xFF"
    sat[4:8] = b"\xFE\xFF\xFF\xFF"
    sat[8:12] = b"\xFE\xFF\xFF\xFF"
    for i in range(3, 128):
        sat[i*4:(i+1)*4] = b"\xFF\xFF\xFF\xFF"

    dir_sec = bytearray(512)
    root_name = "Root Entry\x00".encode("utf-16le")
    dir_sec[0:len(root_name)] = root_name
    dir_sec[64:66] = len(root_name).to_bytes(2, "little")
    dir_sec[66] = 5
    dir_sec[67] = 1
    dir_sec[68:72] = b"\xFF\xFF\xFF\xFF"
    dir_sec[72:76] = b"\xFF\xFF\xFF\xFF"
    dir_sec[76:80] = b"\x01\x00\x00\x00"

    # User stream entry
    s_name = (stream_name + "\x00").encode("utf-16le")
    dir_sec[128:128+len(s_name)] = s_name
    dir_sec[192:194] = len(s_name).to_bytes(2, "little")
    dir_sec[194] = 2
    dir_sec[195] = 1
    dir_sec[196:200] = b"\xFF\xFF\xFF\xFF"
    dir_sec[200:204] = b"\xFF\xFF\xFF\xFF"
    dir_sec[204:208] = b"\xFF\xFF\xFF\xFF"
    dir_sec[244:248] = b"\x02\x00\x00\x00"
    dir_sec[248:252] = len(stream_data).to_bytes(4, "little")

    stream_sec = bytearray(512)
    stream_sec[0:len(stream_data)] = stream_data

    data = bytes(header) + bytes(sat) + bytes(dir_sec) + bytes(stream_sec)
    with open(target_path, "wb") as f:
        f.write(data)

    return target_path


def generate_all_fixtures() -> Dict[str, Path]:
    """Generate the full set of 10 test fixtures required for testing."""
    fixtures = {}
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Valid Benign DOC (OLE)
    fixtures["valid_doc"] = create_minimal_ole(SAMPLE_DIR / "sample_benign.doc")

    # 2. Valid Benign XLS (OLE)
    fixtures["valid_xls"] = create_minimal_ole(SAMPLE_DIR / "sample_benign.xls", b"Excel Workbook Data", "Workbook")

    # 3. Valid Benign OpenXML without macros (.docx or .docm without vba)
    fixtures["docm_nomacro"] = create_minimal_openxml(SAMPLE_DIR / "sample_clean.docm")

    # 4. Valid XLSM without macros
    fixtures["xlsm_nomacro"] = create_minimal_openxml(SAMPLE_DIR / "sample_clean.xlsm", is_excel=True)

    # 5. Document with a harmless VBA macro
    harmless_vba = """Sub Document_Open()
    MsgBox "Hello World - Benign Macro"
End Sub"""
    fixtures["docm_harmless_vba"] = create_minimal_openxml(SAMPLE_DIR / "sample_harmless_macro.docm", vba_code=harmless_vba)

    # 6. Corrupt document
    corrupt_file = SAMPLE_DIR / "sample_corrupt.doc"
    with open(corrupt_file, "wb") as f:
        f.write(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1CORRUPT_BYTES_TRUNCATED")
    fixtures["corrupt_doc"] = corrupt_file

    # 7. Empty file
    empty_file = SAMPLE_DIR / "sample_empty.docm"
    with open(empty_file, "wb") as f:
        pass
    fixtures["empty_file"] = empty_file

    # 8. Unsupported file
    unsupported_file = SAMPLE_DIR / "sample_unsupported.txt"
    with open(unsupported_file, "w") as f:
        f.write("This is a plain text file, not an Office document.")
    fixtures["unsupported_file"] = unsupported_file

    # 9. Malformed ZIP archive
    bad_zip = SAMPLE_DIR / "sample_bad_archive.docm"
    with open(bad_zip, "wb") as f:
        f.write(b"\x50\x4B\x03\x04BAD_ZIP_BODY_TRUNCATED")
    fixtures["malformed_zip"] = bad_zip

    # 10. Zip slip fixture
    slip_zip = SAMPLE_DIR / "sample_zip_slip.docm"
    with zipfile.ZipFile(slip_zip, "w") as z:
        z.writestr("../../etc/passwd", "malicious_content")
        z.writestr("word/document.xml", "<xml></xml>")
    fixtures["zip_slip"] = slip_zip

    return fixtures


if __name__ == "__main__":
    generated = generate_all_fixtures()
    print(f"Generated {len(generated)} test fixtures in {SAMPLE_DIR}")

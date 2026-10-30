"""
ROR13 API Hash Resolution Module.
Implements the canonical 32-bit ROR13 hash algorithm utilized by shellcode families
(Metasploit, Cobalt Strike, standard stagers) to resolve Windows API exports dynamically.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class ResolvedApiHash:
    """Represents a matched Win32 API hash."""
    hash_value_hex: str
    hash_value_int: int
    api_name: str
    module_name: str
    algorithm: str = "ROR13_32"


def ror13_hash(name: str, seed: int = 0) -> int:
    """
    Calculate 32-bit ROR13 hash for an ASCII API name.
    Formula: hash = ((hash >> 13) | ((hash << 19) & 0xFFFFFFFF)) + char_code
    """
    h = seed & 0xFFFFFFFF
    for char in name:
        # Rotate right 13 bits in 32-bit space
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(char)) & 0xFFFFFFFF
    return h


# Reference database of common Win32 APIs targeted by shellcode stagers
KNOWN_WIN32_APIS = [
    # Kernel32
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "LoadLibraryW"),
    ("kernel32.dll", "GetProcAddress"),
    ("kernel32.dll", "VirtualAlloc"),
    ("kernel32.dll", "VirtualAllocEx"),
    ("kernel32.dll", "VirtualProtect"),
    ("kernel32.dll", "VirtualProtectEx"),
    ("kernel32.dll", "CreateThread"),
    ("kernel32.dll", "CreateRemoteThread"),
    ("kernel32.dll", "CreateProcessA"),
    ("kernel32.dll", "CreateProcessW"),
    ("kernel32.dll", "WinExec"),
    ("kernel32.dll", "ExitProcess"),
    ("kernel32.dll", "RtlMoveMemory"),
    ("kernel32.dll", "WriteProcessMemory"),
    ("kernel32.dll", "Sleep"),
    ("kernel32.dll", "WaitForSingleObject"),

    # Urlmon
    ("urlmon.dll", "URLDownloadToFileA"),
    ("urlmon.dll", "URLDownloadToFileW"),

    # Ws2_32
    ("ws2_32.dll", "WSAStartup"),
    ("ws2_32.dll", "WSASocketA"),
    ("ws2_32.dll", "connect"),
    ("ws2_32.dll", "send"),
    ("ws2_32.dll", "recv"),
    ("ws2_32.dll", "closesocket"),

    # Ntdll
    ("ntdll.dll", "NtAllocateVirtualMemory"),
    ("ntdll.dll", "NtWriteVirtualMemory"),
    ("ntdll.dll", "NtCreateThreadEx"),
]


class ApiHashResolver:
    """Precomputes and resolves 32-bit ROR13 API hashes against known Windows functions."""

    def __init__(self):
        # Precompute table: hash_int -> (module, api_name)
        self.hash_table: Dict[int, Tuple[str, str]] = {}
        for mod, api in KNOWN_WIN32_APIS:
            val = ror13_hash(api)
            self.hash_table[val] = (mod, api)

    def resolve_hash(self, hash_val: int) -> Optional[ResolvedApiHash]:
        """Lookup an integer or hex hash value."""
        norm_val = hash_val & 0xFFFFFFFF
        if norm_val in self.hash_table:
            mod, api = self.hash_table[norm_val]
            return ResolvedApiHash(
                hash_value_hex=f"0x{norm_val:08X}",
                hash_value_int=norm_val,
                api_name=api,
                module_name=mod
            )
        return None

    def scan_buffer_for_hashes(self, buffer: bytes) -> List[ResolvedApiHash]:
        """
        Scan a candidate binary buffer (e.g. shellcode) for 4-byte little-endian ROR13 hashes.
        """
        resolved: List[ResolvedApiHash] = []
        if len(buffer) < 4:
            return resolved

        seen = set()
        for i in range(len(buffer) - 3):
            # Read 4 bytes as little-endian uint32
            val = int.from_bytes(buffer[i:i+4], byteorder="little")
            if val in self.hash_table and val not in seen:
                seen.add(val)
                mod, api = self.hash_table[val]
                resolved.append(ResolvedApiHash(
                    hash_value_hex=f"0x{val:08X}",
                    hash_value_int=val,
                    api_name=api,
                    module_name=mod
                ))
        return resolved

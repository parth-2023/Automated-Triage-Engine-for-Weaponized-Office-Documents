"""
ROR13 API Hash Resolution Module.

Implements documented variants of the canonical 32-bit ROR13 hash algorithm
utilized by shellcode families (Metasploit, Cobalt Strike, standard stagers)
to resolve Windows API exports dynamically.

SUPPORTED HASHING VARIANTS & SPECIFICATIONS:

1. ROR13_API_ONLY (Canonical):
   - Rotation direction: Right
   - Rotation amount: 13 bits
   - Integer width: 32-bit unsigned (modulo 2^32)
   - Initial seed: 0
   - Input: API function name (ASCII, case-preserved)
   - Null terminator: Excluded
   - Formula: hash = (((hash >> 13) | (hash << 19)) & 0xFFFFFFFF) + byte
   - Known Reference Vector: "LoadLibraryA" -> 0xEC0E4E8E, "VirtualAlloc" -> 0x91AFCA54

2. ROR13_API_UPPER:
   - Same as ROR13_API_ONLY, but API name is upper-cased before hashing.
   - Useful for shellcode that normalizes export strings with uppercase comparisons.

3. ROR13_API_NULL_TERM:
   - Same as ROR13_API_ONLY, but includes the trailing 0x00 null terminator in the hash.

4. ROR13_MOD_API_SUM:
   - Metasploit stager convention combining module hash and function hash:
     hash = (ROR13(module_name) + ROR13(api_name)) & 0xFFFFFFFF

NOTE ON CUSTOM SEEDS:
  The low-level helper `ror13_hash(name, seed=...)` supports an optional non-zero initial
  seed for deterministic custom hashing. However, `ApiHashResolver` resolves hashes against
  the 4 standard zero-seed variants above; it does not claim to enumerate or dynamically
  resolve arbitrary custom seeds without an explicit precomputed reference table.

LIMITATIONS:
  - When a hash value does not match known Windows APIs in the reference database,
    it is reported as UNRESOLVED. The engine never invents or hallucinates an API name.
  - Matches report the specific algorithm variant and confidence.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class ResolvedApiHash:
    """Represents a matched Win32 API hash with full provenance."""
    hash_value_hex: str
    hash_value_int: int
    api_name: str
    module_name: str
    algorithm: str = "ROR13_API_ONLY"
    confidence: str = "High"


def ror13_hash(name: str, seed: int = 0, include_null: bool = False) -> int:
    """
    Calculate 32-bit ROR13 hash for a string.

    Parameters
    ----------
    name         : ASCII string to hash.
    seed         : Initial 32-bit unsigned seed (default 0).
    include_null : If True, appends trailing null byte to the hash calculation.
    """
    h = seed & 0xFFFFFFFF
    for char in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(char)) & 0xFFFFFFFF
    if include_null:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
    return h


def ror13_mod_api_sum(module_name: str, api_name: str) -> int:
    """
    Calculate combined Metasploit-style module + API hash.
    hash = (ror13(module) + ror13(api)) & 0xFFFFFFFF
    """
    h_mod = ror13_hash(module_name)
    h_api = ror13_hash(api_name)
    return (h_mod + h_api) & 0xFFFFFFFF


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
        # Precompute table: hash_int -> (module, api_name, algorithm, confidence)
        self.hash_table: Dict[int, Tuple[str, str, str, str]] = {}

        for mod, api in KNOWN_WIN32_APIS:
            # 1. Canonical ROR13_API_ONLY
            v1 = ror13_hash(api)
            self.hash_table[v1] = (mod, api, "ROR13_API_ONLY", "High")

            # 2. ROR13_API_UPPER
            v2 = ror13_hash(api.upper())
            if v2 not in self.hash_table:
                self.hash_table[v2] = (mod, api, "ROR13_API_UPPER", "High")

            # 3. ROR13_API_NULL_TERM
            v3 = ror13_hash(api, include_null=True)
            if v3 not in self.hash_table:
                self.hash_table[v3] = (mod, api, "ROR13_API_NULL_TERM", "Medium")

            # 4. ROR13_MOD_API_SUM
            v4 = ror13_mod_api_sum(mod, api)
            if v4 not in self.hash_table:
                self.hash_table[v4] = (mod, api, "ROR13_MOD_API_SUM", "High")

            # Also uppercase module sum
            v5 = ror13_mod_api_sum(mod.upper(), api)
            if v5 not in self.hash_table:
                self.hash_table[v5] = (mod, api, "ROR13_MOD_API_SUM", "Medium")

    def resolve_hash(self, hash_val: int) -> Optional[ResolvedApiHash]:
        """Lookup an integer or hex hash value across all supported algorithm variants."""
        norm_val = hash_val & 0xFFFFFFFF
        if norm_val in self.hash_table:
            mod, api, algo, conf = self.hash_table[norm_val]
            return ResolvedApiHash(
                hash_value_hex=f"0x{norm_val:08X}",
                hash_value_int=norm_val,
                api_name=api,
                module_name=mod,
                algorithm=algo,
                confidence=conf
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
                mod, api, algo, conf = self.hash_table[val]
                resolved.append(ResolvedApiHash(
                    hash_value_hex=f"0x{val:08X}",
                    hash_value_int=val,
                    api_name=api,
                    module_name=mod,
                    algorithm=algo,
                    confidence=conf
                ))
        return resolved

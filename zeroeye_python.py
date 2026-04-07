import ctypes
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, List, Optional

import pefile
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog


IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
CLR_DIRECTORY_INDEX = 14
MAX_DEPTH_SEARCH = 2

SYSTEM_DLL_PREFIXES = ("api-ms-", "ext-ms-")
SYSTEM_DLL_NAMES = {
    "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll", "ws2_32.dll",
    "comdlg32.dll", "comctl32.dll", "version.dll", "setupapi.dll", "winmm.dll",
    "bcrypt.dll", "crypt32.dll", "rpcrt4.dll", "shlwapi.dll", "sechost.dll",
    "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll", "vcruntime140_1.dll",
    "msvcp140.dll", "imm32.dll", "combase.dll", "cfgmgr32.dll", "wintrust.dll",
}
DRIVER_RISK_IMPORTS = {
    "ZwTerminateProcess", "ZwOpenProcess", "ZwWriteFile", "ZwDeleteFile",
    "ZwMapViewOfSection", "MmMapIoSpace", "MmCopyVirtualMemory", "MmProtectMdlSystemAddress",
    "IoCreateDevice", "IoCreateSymbolicLink", "PsLookupProcessByProcessId",
}


def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)}{unit}"
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{size}B"


def normalize_scan_types(value: str) -> set[str]:
    raw = {item.strip().lower() for item in value.split(",") if item.strip()}
    if not raw or "all" in raw:
        return {"gui", "cmd", "dotnet", "sys", "exe"}
    if "gui" in raw or "cmd" in raw:
        raw.add("exe")
    return raw


def match_numeric_filter(value: int, condition: str) -> bool:
    text = condition.strip()
    if not text:
        return True
    range_match = re.fullmatch(r"\s*(-?\d+)\s*(?:\.\.|-)\s*(-?\d+)\s*", text)
    if range_match:
        left, right = range_match.groups()
        try:
            low = int(left)
            high = int(right)
        except ValueError:
            return False
        if low > high:
            low, high = high, low
        return low <= value <= high
    if ".." in text:
        left, _, right = text.partition("..")
        if left.strip():
            try:
                if value < int(left.strip()):
                    return False
            except ValueError:
                return False
        if right.strip():
            try:
                if value > int(right.strip()):
                    return False
            except ValueError:
                return False
        return True
    for op in (">=", "<=", "==", ">", "<", "="):
        if text.startswith(op):
            try:
                target = int(text[len(op):].strip())
            except ValueError:
                return False
            if op == ">=":
                return value >= target
            if op == "<=":
                return value <= target
            if op in {"==", "="}:
                return value == target
            if op == ">":
                return value > target
            if op == "<":
                return value < target
    try:
        return value == int(text)
    except ValueError:
        return False


def is_system_dll(name: str) -> bool:
    low = name.lower()
    return low in SYSTEM_DLL_NAMES or low.startswith(SYSTEM_DLL_PREFIXES)


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def unique_dir(path: Path) -> Path:
    if not path.exists():
        return path
    index = 2
    while True:
        candidate = Path(f"{path}({index})")
        if not candidate.exists():
            return candidate
        index += 1


def undecorate_symbol(name: str) -> str:
    try:
        dbghelp = ctypes.WinDLL("dbghelp")
        func = dbghelp.UnDecorateSymbolName
        func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32]
        func.restype = ctypes.c_uint32
        buf = ctypes.create_string_buffer(4096)
        result = func(name.encode("utf-8", errors="ignore"), buf, len(buf), 0)
        if result:
            return buf.value.decode("utf-8", errors="ignore")
    except Exception:
        pass
    return name


def read_c_string(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end == -1:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="ignore")


@dataclass
class ExportEntry:
    ordinal: int
    name: str
    undecorated: str
    rva: int


@dataclass
class DotNetInfo:
    is_dotnet: bool = False
    is_net_core: bool = False
    config_exists: bool = False
    config_can_create: bool = False
    deps_json_exists: bool = False
    runtime_config_exists: bool = False
    pinvoke_targets: List[str] = field(default_factory=list)
    assembly_refs: List[str] = field(default_factory=list)
    all_assembly_refs: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    path: Path
    exists: bool
    valid_pe: bool = False
    arch: str = "unknown"
    file_kind: str = "unknown"
    display_type: str = "unknown"
    is_dotnet: bool = False
    is_driver: bool = False
    is_gui: bool = False
    is_cmd: bool = False
    signed: bool = False
    signer: str = ""
    size: int = 0
    imports: List[str] = field(default_factory=list)
    import_functions: List[str] = field(default_factory=list)
    exports: List[ExportEntry] = field(default_factory=list)
    dotnet: DotNetInfo = field(default_factory=DotNetInfo)
    risky_driver_imports: List[str] = field(default_factory=list)
    resolved_dependencies: List[str] = field(default_factory=list)


class DotNetMetadataParser:
    TABLE_MODULE_REF = 0x1A
    TABLE_ASSEMBLY_REF = 0x23

    CODED_INDEX_TABLES = {
        "ResolutionScope": (2, [0x00, 0x1A, 0x23, 0x01]),
        "TypeDefOrRef": (2, [0x02, 0x01, 0x1B]),
        "MemberRefParent": (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
        "MemberForwarded": (1, [0x04, 0x06]),
        "Implementation": (2, [0x26, 0x23, 0x27]),
        "CustomAttributeType": (3, [-1, -1, 0x06, 0x0A, -1]),
        "TypeOrMethodDef": (1, [0x02, 0x06]),
        "HasConstant": (2, [0x04, 0x08, 0x17]),
        "HasCustomAttribute": (5, [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A]),
        "HasFieldMarshal": (1, [0x04, 0x08]),
        "HasDeclSecurity": (2, [0x02, 0x06, 0x20]),
        "HasSemantics": (1, [0x14, 0x17]),
        "MethodDefOrRef": (1, [0x06, 0x0A]),
    }

    TABLE_DEFS = {
        0x00: [("fixed2", None), ("string", None), ("guid", None), ("guid", None), ("guid", None)],
        0x01: [("coded", "ResolutionScope"), ("string", None), ("string", None)],
        0x02: [("fixed4", None), ("string", None), ("string", None), ("coded", "TypeDefOrRef"), ("idx", 0x04), ("idx", 0x06)],
        0x04: [("fixed2", None), ("string", None), ("blob", None)],
        0x06: [("fixed4", None), ("fixed2", None), ("fixed2", None), ("string", None), ("blob", None), ("idx", 0x08)],
        0x08: [("fixed2", None), ("fixed2", None), ("string", None)],
        0x09: [("idx", 0x02), ("coded", "TypeDefOrRef")],
        0x0A: [("coded", "MemberRefParent"), ("string", None), ("blob", None)],
        0x0B: [("fixed2", None), ("coded", "HasConstant"), ("blob", None)],
        0x0C: [("coded", "HasCustomAttribute"), ("coded", "CustomAttributeType"), ("blob", None)],
        0x0D: [("coded", "HasFieldMarshal"), ("blob", None)],
        0x0E: [("fixed2", None), ("coded", "HasDeclSecurity"), ("blob", None)],
        0x0F: [("fixed2", None), ("fixed4", None), ("idx", 0x02)],
        0x10: [("fixed4", None), ("idx", 0x04)],
        0x11: [("blob", None)],
        0x12: [("idx", 0x02), ("idx", 0x14)],
        0x14: [("fixed2", None), ("string", None), ("coded", "TypeDefOrRef")],
        0x15: [("idx", 0x02), ("idx", 0x17)],
        0x17: [("fixed2", None), ("string", None), ("blob", None)],
        0x18: [("fixed2", None), ("idx", 0x06), ("coded", "HasSemantics")],
        0x19: [("idx", 0x02), ("coded", "MethodDefOrRef"), ("coded", "MethodDefOrRef")],
        0x1A: [("string", None)],
        0x1B: [("blob", None)],
        0x1C: [("fixed2", None), ("coded", "MemberForwarded"), ("string", None), ("idx", 0x1A)],
        0x1D: [("fixed4", None), ("idx", 0x04)],
        0x20: [("fixed4", None), ("fixed2", None), ("fixed2", None), ("fixed2", None), ("fixed2", None), ("fixed4", None), ("blob", None), ("string", None), ("string", None)],
        0x21: [("fixed4", None)],
        0x22: [("fixed4", None), ("fixed4", None), ("fixed4", None)],
        0x23: [("fixed2", None), ("fixed2", None), ("fixed2", None), ("fixed2", None), ("fixed4", None), ("blob", None), ("string", None), ("string", None), ("blob", None)],
        0x24: [("fixed4", None), ("idx", 0x23)],
        0x25: [("fixed4", None), ("fixed4", None), ("fixed4", None), ("idx", 0x23)],
        0x26: [("fixed4", None), ("string", None), ("blob", None)],
        0x27: [("fixed4", None), ("fixed4", None), ("string", None), ("string", None), ("coded", "Implementation")],
        0x28: [("fixed4", None), ("fixed4", None), ("string", None), ("coded", "Implementation")],
        0x29: [("idx", 0x02), ("idx", 0x02)],
        0x2A: [("fixed2", None), ("fixed2", None), ("coded", "TypeOrMethodDef"), ("string", None)],
        0x2B: [("coded", "MethodDefOrRef"), ("blob", None)],
        0x2C: [("idx", 0x2A), ("coded", "TypeDefOrRef")],
    }

    SYSTEM_ASSEMBLY_PREFIXES = ("System.",)
    SYSTEM_ASSEMBLIES = {
        "mscorlib", "netstandard", "System", "WindowsBase",
        "PresentationCore", "PresentationFramework", "UIAutomationProvider",
        "Microsoft.CSharp",
    }

    def __init__(self, pe: pefile.PE, path: Path):
        self.pe = pe
        self.path = path

    def analyze(self) -> DotNetInfo:
        info = DotNetInfo(is_dotnet=self._is_dotnet())
        if not info.is_dotnet:
            return info
        info.config_exists = self.path.with_suffix(self.path.suffix + ".config").exists()
        info.config_can_create = not info.config_exists
        info.deps_json_exists = self.path.with_name(f"{self.path.stem}.deps.json").exists()
        info.runtime_config_exists = self.path.with_name(f"{self.path.stem}.runtimeconfig.json").exists()
        info.is_net_core = info.deps_json_exists or info.runtime_config_exists
        try:
            metadata_root = self._get_metadata_root()
            if not metadata_root:
                return info
            module_refs, assembly_refs = self._read_tables(metadata_root)
            info.pinvoke_targets = sorted({name for name in module_refs if name})
            info.all_assembly_refs = sorted({name for name in assembly_refs if name})
            info.assembly_refs = sorted({name for name in info.all_assembly_refs if not self._is_system_assembly(name)})
        except Exception:
            return info
        return info

    def _is_dotnet(self) -> bool:
        directories = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY
        return len(directories) > CLR_DIRECTORY_INDEX and directories[CLR_DIRECTORY_INDEX].VirtualAddress != 0

    def _rva_to_data(self, rva: int, size: int) -> bytes:
        offset = self.pe.get_offset_from_rva(rva)
        return self.pe.__data__[offset:offset + size]

    def _get_metadata_root(self) -> Optional[bytes]:
        clr_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[CLR_DIRECTORY_INDEX]
        if clr_dir.VirtualAddress == 0:
            return None
        clr_offset = self.pe.get_offset_from_rva(clr_dir.VirtualAddress)
        data = self.pe.__data__[clr_offset:clr_offset + clr_dir.Size]
        if len(data) < 16:
            return None
        metadata_rva = int.from_bytes(data[8:12], "little")
        metadata_size = int.from_bytes(data[12:16], "little")
        return self._rva_to_data(metadata_rva, metadata_size)

    def _read_tables(self, blob: bytes) -> tuple[list[str], list[str]]:
        if blob[:4] != b"BSJB":
            return [], []
        version_len = int.from_bytes(blob[12:16], "little")
        pos = 16 + version_len
        pos = (pos + 3) & ~3
        if pos + 4 > len(blob):
            return [], []
        streams = int.from_bytes(blob[pos + 2:pos + 4], "little")
        pos += 4
        stream_map = {}
        for _ in range(streams):
            if pos + 8 > len(blob):
                return [], []
            offset = int.from_bytes(blob[pos:pos + 4], "little")
            size = int.from_bytes(blob[pos + 4:pos + 8], "little")
            pos += 8
            end = blob.find(b"\x00", pos)
            if end == -1:
                return [], []
            name = blob[pos:end].decode("utf-8", errors="ignore")
            pos = (end + 4) & ~3
            stream_map[name] = blob[offset:offset + size]
        tables_stream = stream_map.get("#~") or stream_map.get("#-")
        strings_stream = stream_map.get("#Strings", b"")
        if not tables_stream or len(tables_stream) < 24:
            return [], []
        heap_sizes = tables_stream[6]
        valid_mask = int.from_bytes(tables_stream[8:16], "little")
        cursor = 24
        row_counts = [0] * 64
        present_tables = []
        for table_id in range(64):
            if (valid_mask >> table_id) & 1:
                row_counts[table_id] = int.from_bytes(tables_stream[cursor:cursor + 4], "little")
                cursor += 4
                present_tables.append(table_id)
        table_offsets = {}
        for table_id in present_tables:
            table_offsets[table_id] = cursor
            cursor += self._table_row_size(table_id, heap_sizes, row_counts) * row_counts[table_id]

        module_refs = self._read_module_refs(tables_stream, strings_stream, table_offsets, heap_sizes, row_counts)
        assembly_refs = self._read_assembly_refs(tables_stream, strings_stream, table_offsets, heap_sizes, row_counts)
        return module_refs, assembly_refs

    def _read_module_refs(self, tables_stream, strings_stream, table_offsets, heap_sizes, row_counts):
        if self.TABLE_MODULE_REF not in table_offsets:
            return []
        row_size = self._table_row_size(self.TABLE_MODULE_REF, heap_sizes, row_counts)
        width = self._column_width(("string", None), heap_sizes, row_counts)
        values = []
        for idx in range(row_counts[self.TABLE_MODULE_REF]):
            start = table_offsets[self.TABLE_MODULE_REF] + idx * row_size
            name_index = int.from_bytes(tables_stream[start:start + width], "little")
            name = read_c_string(strings_stream, name_index)
            if name:
                values.append(name)
        return values

    def _read_assembly_refs(self, tables_stream, strings_stream, table_offsets, heap_sizes, row_counts):
        if self.TABLE_ASSEMBLY_REF not in table_offsets:
            return []
        row_size = self._table_row_size(self.TABLE_ASSEMBLY_REF, heap_sizes, row_counts)
        defs = self.TABLE_DEFS[self.TABLE_ASSEMBLY_REF]
        values = []
        for idx in range(row_counts[self.TABLE_ASSEMBLY_REF]):
            start = table_offsets[self.TABLE_ASSEMBLY_REF] + idx * row_size
            row = tables_stream[start:start + row_size]
            offset = 0
            cols = []
            for col in defs:
                width = self._column_width(col, heap_sizes, row_counts)
                cols.append(int.from_bytes(row[offset:offset + width], "little"))
                offset += width
            name = read_c_string(strings_stream, cols[6])
            if name:
                values.append(name)
        return values

    def _table_row_size(self, table_id: int, heap_sizes: int, row_counts: list[int]) -> int:
        return sum(self._column_width(col, heap_sizes, row_counts) for col in self.TABLE_DEFS.get(table_id, []))

    def _column_width(self, col: tuple[str, object], heap_sizes: int, row_counts: list[int]) -> int:
        kind, extra = col
        if kind == "fixed2":
            return 2
        if kind == "fixed4":
            return 4
        if kind == "string":
            return 4 if heap_sizes & 0x01 else 2
        if kind == "guid":
            return 4 if heap_sizes & 0x02 else 2
        if kind == "blob":
            return 4 if heap_sizes & 0x04 else 2
        if kind == "idx":
            return 4 if row_counts[extra] > 0xFFFF else 2
        if kind == "coded":
            tag_bits, tables = self.CODED_INDEX_TABLES[extra]
            max_rows = max((row_counts[t] for t in tables if 0 <= t < len(row_counts)), default=0)
            return 2 if max_rows < (1 << (16 - tag_bits)) else 4
        return 2

    def _is_system_assembly(self, name: str) -> bool:
        if name in self.SYSTEM_ASSEMBLIES:
            return True
        if name.startswith(self.SYSTEM_ASSEMBLY_PREFIXES):
            return True
        if name.startswith("Microsoft.Win32.") or name.startswith("Microsoft.Extensions."):
            return True
        return False


class ZeroEyeAnalyzer:
    def __init__(self, logger: Optional[Callable[[str], None]] = None):
        self.logger = logger or (lambda _msg: None)

    def log(self, message: str) -> None:
        self.logger(message)

    def analyze_file(self, path: str | Path) -> AnalysisResult:
        target = Path(path)
        result = AnalysisResult(path=target, exists=target.exists(), size=target.stat().st_size if target.exists() else 0)
        if not result.exists:
            return result
        try:
            pe = pefile.PE(str(target), fast_load=False)
            result.valid_pe = True
            result.arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86" if pe.FILE_HEADER.Machine == 0x14C else hex(pe.FILE_HEADER.Machine)
            suffix = target.suffix.lower()
            result.is_driver = suffix == ".sys"
            result.is_dotnet = len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > CLR_DIRECTORY_INDEX and pe.OPTIONAL_HEADER.DATA_DIRECTORY[CLR_DIRECTORY_INDEX].VirtualAddress != 0
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            result.is_gui = subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI
            result.is_cmd = subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI

            if result.is_driver:
                result.file_kind = "sys"
            elif result.is_dotnet:
                result.file_kind = "dotnet"
            elif suffix == ".dll":
                result.file_kind = "dll"
            elif suffix == ".exe":
                result.file_kind = "gui" if result.is_gui else "cmd" if result.is_cmd else "exe"

            result.display_type = result.file_kind
            result.imports = self._read_import_dlls(pe)
            result.import_functions = self._read_import_functions(pe)
            result.exports = self._read_exports(pe)
            result.signed, result.signer = self._get_signature_info(target)
            if result.is_driver:
                imported = set(result.import_functions)
                result.risky_driver_imports = sorted(name for name in imported if name in DRIVER_RISK_IMPORTS)
            if result.is_dotnet:
                result.dotnet = DotNetMetadataParser(pe, target).analyze()
            pe.close()
        except Exception:
            return result
        return result

    def list_imports(self, path: str | Path) -> list[str]:
        result = self.analyze_file(path)
        lines = []
        dll_groups = {}
        for item in result.import_functions:
            dll, _, func = item.partition("!")
            dll_groups.setdefault(dll, []).append(func)
        for dll in sorted(dll_groups):
            lines.append(f"[{dll}]")
            lines.extend(f"  {func}" for func in dll_groups[dll])
        return lines or ["No imports found."]

    def list_exports(self, path: str | Path) -> list[str]:
        result = self.analyze_file(path)
        if not result.exports:
            return ["No exports found."]
        return [f"ord={item.ordinal} rva=0x{item.rva:08X} name={item.name} undec={item.undecorated}" for item in result.exports]

    def summarize_result(self, result: AnalysisResult) -> list[str]:
        if not result.exists:
            return [f"Missing file: {result.path}"]
        if not result.valid_pe:
            return [f"Not a valid PE: {result.path}"]
        lines = [
            f"Path: {result.path}",
            f"Type: {result.file_kind}",
            f"Arch: {result.arch}",
            f"Size: {format_size(result.size)}",
            f"Signed: {'yes' if result.signed else 'no'}{f' ({result.signer})' if result.signer else ''}",
            f"Imports: {len(result.imports)} DLL(s), {len(result.import_functions)} function(s)",
            f"Exports: {len(result.exports)}",
        ]
        if result.is_dotnet:
            lines.extend([
                f".NET runtime: {'Core/5+' if result.dotnet.is_net_core else 'Framework'}",
                f"P/Invoke targets: {', '.join(result.dotnet.pinvoke_targets) or 'none'}",
                f"Assembly refs: {', '.join(result.dotnet.assembly_refs) or 'none'}",
            ])
        if result.is_driver:
            lines.append(f"Driver risky APIs: {', '.join(result.risky_driver_imports) or 'none'}")
        return lines

    def generate_for_target(self, path: str | Path, output_root: str | Path) -> Path:
        result = self.analyze_file(path)
        if not result.valid_pe:
            raise ValueError("Target is not a valid PE file")
        if result.is_dotnet:
            return self._generate_dotnet_bundle(result, Path(output_root))
        if result.is_driver:
            return self._generate_driver_bundle(result, Path(output_root))
        return self._generate_native_bundle(result, Path(output_root))

    def scan_directory(self, root_dir: str | Path, output_root: str | Path, scan_types: str = "all", signed_only: bool = False, arch_filter: str = "all", exclude_patterns: str = "", exclude_system_only: bool = False, import_dll_count_filter: str = "", should_stop: Optional[Callable[[], bool]] = None) -> list[Path]:
        root = Path(root_dir)
        if not root.exists():
            raise FileNotFoundError(root)
        types = normalize_scan_types(scan_types)
        patterns = [p.strip().lower() for p in exclude_patterns.split("|") if p.strip()]
        outputs = []
        matched_results: list[AnalysisResult] = []
        for path in root.rglob("*"):
            if should_stop and should_stop():
                self.log("Scan stopped by user.")
                break
            if not path.is_file() or path.suffix.lower() not in {".exe", ".dll", ".sys"}:
                continue
            result = self.analyze_file(path)
            if not result.valid_pe:
                continue
            if arch_filter in {"x64", "64"} and result.arch != "x64":
                continue
            if arch_filter in {"x86", "86"} and result.arch != "x86":
                continue
            if signed_only and not result.signed:
                continue
            if patterns and any(p in path.name.lower() for p in patterns):
                continue
            if not self._matches_scan_types(result, types):
                continue
            if not match_numeric_filter(len(result.imports), import_dll_count_filter):
                continue
            if exclude_system_only and result.file_kind in {"gui", "cmd", "exe"} and self._only_system_imports(result):
                continue
            matched_results.append(result)
            if result.is_driver:
                outputs.append(self._generate_driver_bundle(result, Path(output_root)))
            elif result.is_dotnet:
                outputs.append(self._generate_dotnet_bundle(result, Path(output_root)))
            else:
                outputs.append(self._generate_native_bundle(result, Path(output_root)))
        self._write_scan_manifest(
            output_root=Path(output_root),
            root_dir=root,
            scan_types=scan_types,
            signed_only=signed_only,
            arch_filter=arch_filter,
            exclude_patterns=exclude_patterns,
            exclude_system_only=exclude_system_only,
            import_dll_count_filter=import_dll_count_filter,
            matched_results=matched_results,
            output_dirs=outputs,
        )
        return outputs

    def _write_scan_manifest(
        self,
        output_root: Path,
        root_dir: Path,
        scan_types: str,
        signed_only: bool,
        arch_filter: str,
        exclude_patterns: str,
        exclude_system_only: bool,
        import_dll_count_filter: str,
        matched_results: list[AnalysisResult],
        output_dirs: list[Path],
    ) -> None:
        reports_dir = ensure_dir(output_root / "Eyebin" / "scan_reports")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = reports_dir / f"scan_manifest_{stamp}.txt"
        lines = [
            f"Root: {root_dir}",
            f"Types: {scan_types}",
            f"Arch: {arch_filter}",
            f"Signed only: {signed_only}",
            f"Exclude DLL patterns: {exclude_patterns or 'none'}",
            f"Exclude system-only EXE: {exclude_system_only}",
            f"Import DLL count filter: {import_dll_count_filter or 'none'}",
            f"Matched files: {len(matched_results)}",
            f"Generated directories: {len(output_dirs)}",
            "",
            "Matches:",
        ]
        if matched_results:
            for result in matched_results:
                lines.append(
                    f"- [{result.file_kind}/{result.arch}/imports={len(result.imports)}] {result.path}"
                )
        else:
            lines.append("- none")
        lines.append("")
        lines.append("Output directories:")
        if output_dirs:
            for item in output_dirs:
                lines.append(f"- {item}")
        else:
            lines.append("- none")
        report_path.write_text("\n".join(lines), encoding="utf-8")
        self.log(f"Scan manifest: {report_path}")

    def _matches_scan_types(self, result: AnalysisResult, types: set[str]) -> bool:
        if result.is_driver:
            return "sys" in types
        if result.is_dotnet:
            return "dotnet" in types
        if result.file_kind == "gui":
            return "gui" in types or "exe" in types
        if result.file_kind == "cmd":
            return "cmd" in types or "exe" in types
        if result.file_kind in {"dll", "exe"}:
            return "exe" in types
        return False

    def _only_system_imports(self, result: AnalysisResult) -> bool:
        imports = [name for name in result.imports if name]
        return bool(imports) and all(is_system_dll(name) for name in imports)

    def _read_import_dlls(self, pe: pefile.PE) -> list[str]:
        dlls = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dlls.append(entry.dll.decode("utf-8", errors="ignore"))
        return sorted(set(dlls))

    def _read_import_functions(self, pe: pefile.PE) -> list[str]:
        funcs = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="ignore")
                for imp in entry.imports:
                    name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                    funcs.append(f"{dll}!{name}")
        return funcs

    def _read_exports(self, pe: pefile.PE) -> list[ExportEntry]:
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = symbol.name.decode("utf-8", errors="ignore") if symbol.name else f"ordinal_{symbol.ordinal}"
                exports.append(ExportEntry(symbol.ordinal, name, undecorate_symbol(name), symbol.address))
        return exports

    def _get_signature_info(self, path: Path) -> tuple[bool, str]:
        if os.name != "nt":
            return False, ""
        escaped_path = str(path).replace("'", "''")
        ps_script = (
            f"$s=Get-AuthenticodeSignature -LiteralPath '{escaped_path}'; "
            "if($s.Status -eq 'Valid'){"
            "$n=''; "
            "if($s.SignerCertificate){$n=$s.SignerCertificate.Subject}; "
            "Write-Output ('VALID|' + $n)"
            "} else {"
            "Write-Output ('INVALID|' + $s.Status)"
            "}"
        )
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            ps_script,
        ]
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
            output = (completed.stdout or "").strip()
            if output.startswith("VALID|"):
                return True, output.partition("|")[2]
        except Exception:
            pass
        return False, ""

    def _candidate_hijack_dlls(self, imports: Iterable[str]) -> list[str]:
        return [name for name in sorted(set(imports)) if not is_system_dll(name)]

    def _resolve_dependencies(self, target_path: Path, names: Iterable[str], recursive: bool = True) -> list[Path]:
        target_names = {name.lower() for name in names if name}
        if not target_names:
            return []
        found: dict[str, Path] = {}
        queue = list(target_names)
        visited = set()

        while queue:
            current_name = queue.pop(0)
            if current_name in visited:
                continue
            visited.add(current_name)
            resolved = self._resolve_single_dependency(target_path, current_name)
            if not resolved:
                continue
            found[current_name] = resolved
            if recursive:
                try:
                    dep_result = self.analyze_file(resolved)
                    for child in self._candidate_hijack_dlls(dep_result.imports):
                        child_low = child.lower()
                        if child_low not in visited and child_low not in found:
                            queue.append(child_low)
                except Exception:
                    continue
        return list(found.values())

    def _resolve_single_dependency(self, target_path: Path, dll_name: str) -> Optional[Path]:
        roots = [target_path.parent]
        if target_path.parent.parent.exists():
            roots.append(target_path.parent.parent)
        if os.name == "nt":
            system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            roots.extend([
                system_root / "System32",
                system_root / "SysWOW64",
                system_root,
            ])
            path_env = os.environ.get("PATH", "")
            for entry in path_env.split(os.pathsep):
                if entry.strip():
                    roots.append(Path(entry.strip()))
        seen_roots: set[Path] = set()
        for root in roots:
            try:
                root = root.resolve()
            except Exception:
                continue
            if root in seen_roots or not root.exists():
                continue
            seen_roots.add(root)
            direct = root / dll_name
            if direct.exists() and direct.is_file():
                return direct
            for file in self._iter_files_limited(root, MAX_DEPTH_SEARCH):
                if file.name.lower() == dll_name.lower():
                    return file
        return None

    def _iter_files_limited(self, root: Path, max_depth: int) -> Iterable[Path]:
        root = root.resolve()
        for current_root, dirs, files in os.walk(root):
            current_path = Path(current_root)
            depth = len(current_path.relative_to(root).parts)
            if depth >= max_depth:
                dirs[:] = []
            for name in files:
                yield current_path / name

    def _generate_native_bundle(self, result: AnalysisResult, output_root: Path) -> Path:
        arch_dir = "x64" if result.arch == "x64" else "x86"
        base_dir = ensure_dir(output_root / "Eyebin" / "Dll" / arch_dir)
        dep_names = self._candidate_hijack_dlls(result.imports)
        folder_name = f"{result.path.stem}[{result.file_kind}-{len(dep_names)}-{format_size(result.size)}]"
        bundle_dir = unique_dir(base_dir / folder_name)
        infos_dir = ensure_dir(bundle_dir / "infos")

        shutil.copy2(result.path, bundle_dir / result.path.name)
        resolved_deps = self._resolve_dependencies(result.path, dep_names, recursive=True)
        result.resolved_dependencies = [str(dep) for dep in resolved_deps]
        for dep in resolved_deps:
            try:
                shutil.copy2(dep, bundle_dir / dep.name)
            except Exception:
                continue

        lines = self.summarize_result(result)
        lines.append("")
        lines.append("Candidate DLLs:")
        if dep_names:
            lines.extend(f"- {name}" for name in dep_names)
        else:
            lines.append("- none")
        lines.append("")
        lines.append("Resolved DLL Paths:")
        if resolved_deps:
            lines.extend(f"- {dep}" for dep in resolved_deps)
        else:
            lines.append("- none")
        (infos_dir / "Info.txt").write_text("\n".join(lines), encoding="utf-8")

        self.log(f"Generated native bundle: {bundle_dir}")
        return bundle_dir

    def _generate_dotnet_bundle(self, result: AnalysisResult, output_root: Path) -> Path:
        arch_dir = "x64" if result.arch == "x64" else "x86"
        base_dir = ensure_dir(output_root / "Eyebin" / "Dll" / arch_dir)
        ref_count = len(result.dotnet.assembly_refs) + len(result.dotnet.pinvoke_targets)
        runtime_label = "dotnet-core" if result.dotnet.is_net_core else "dotnet"
        folder_name = f"{result.path.stem}[{runtime_label}-{ref_count}-{format_size(result.size)}]"
        bundle_dir = unique_dir(base_dir / folder_name)
        infos_dir = ensure_dir(bundle_dir / "infos")

        shutil.copy2(result.path, bundle_dir / result.path.name)
        config_path = result.path.with_suffix(result.path.suffix + ".config")
        if config_path.exists():
            shutil.copy2(config_path, bundle_dir / f"{config_path.name}.bak")

        resolved_deps = self._resolve_dependencies(result.path, result.dotnet.assembly_refs, recursive=False)
        result.resolved_dependencies = [str(dep) for dep in resolved_deps]
        for dep in resolved_deps:
            try:
                shutil.copy2(dep, bundle_dir / dep.name)
            except Exception:
                continue

        info_lines = self.summarize_result(result)
        info_lines.append("")
        info_lines.append("Resolved Assembly Paths:")
        if resolved_deps:
            info_lines.extend(f"- {dep}" for dep in resolved_deps)
        else:
            info_lines.append("- none")
        (infos_dir / "Info.txt").write_text("\n".join(info_lines), encoding="utf-8")
        (bundle_dir / f"{result.path.name}.config").write_text(self._build_dotnet_config(result), encoding="utf-8")
        (infos_dir / f"{result.path.stem}_payload.cs").write_text(self._build_dotnet_payload(result.path.stem), encoding="utf-8")
        self.log(f"Generated .NET bundle: {bundle_dir}")
        return bundle_dir

    def _generate_driver_bundle(self, result: AnalysisResult, output_root: Path) -> Path:
        base_dir = ensure_dir(output_root / "Eyebin" / "Sys")
        folder_name = f"{result.path.stem}[sys-{format_size(result.size)}]"
        bundle_dir = unique_dir(base_dir / folder_name)
        infos_dir = ensure_dir(bundle_dir / "infos")

        shutil.copy2(result.path, bundle_dir / result.path.name)
        lines = self.summarize_result(result)
        lines.append("")
        lines.append("Signer:")
        lines.append(f"- {result.signer or 'unknown'}")
        lines.append("")
        lines.append("Risk imports:")
        if result.risky_driver_imports:
            lines.extend(f"- {name}" for name in result.risky_driver_imports)
        else:
            lines.append("- none")
        (infos_dir / "Info.txt").write_text("\n".join(lines), encoding="utf-8")
        self.log(f"Generated driver bundle: {bundle_dir}")
        return bundle_dir

    def _build_dotnet_config(self, result: AnalysisResult) -> str:
        assembly_name = result.path.stem + "_payload"
        app_domain = result.path.stem + ".PayloadManager.Entry"
        return f"""<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <runtime>
    <appDomainManagerAssembly value="{assembly_name}" />
    <appDomainManagerType value="{app_domain}" />
  </runtime>
</configuration>
"""

    def _build_dotnet_payload(self, stem: str) -> str:
        return f"""using System;
using System.Windows.Forms;

namespace {stem}.PayloadManager
{{
    public sealed class Entry : AppDomainManager
    {{
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {{
            MessageBox.Show("ZeroEye Python payload loaded.", "{stem}");
        }}
    }}
}}
"""


class ZeroEyeWindow:
    LANG = {
        "zh": {
            "title": "BinarySpy ZeroEye",
            "tools_group": "ZeroEye 工具",
            "scan_group": "扫描选项",
            "results_group": "扫描结果",
            "file": "文件",
            "scan_dir": "扫描目录",
            "output": "输出目录",
            "browse": "浏览",
            "types": "类型",
            "arch": "架构",
            "exclude_dll": "排除 DLL 关键字",
            "import_dll_count": "导入 DLL 数条件",
            "signed_only": "仅已签名",
            "exclude_system_only": "排除仅依赖系统 DLL 的 EXE",
            "analyze": "分析文件",
            "view_imports": "查看导入表",
            "view_exports": "查看导出表",
            "scan": "扫描目录",
            "stop_scan": "停止扫描",
            "clear_log": "清空日志",
            "language": "语言/Language",
            "imports_header": "=== 导入表 ===",
            "exports_header": "=== 导出表 ===",
            "output_line": "输出: {}",
            "generated_count": "已生成 {} 个结果目录。",
            "need_scan_dir": "请先选择扫描目录",
            "need_file": "请先选择目标文件",
            "missing_file": "目标文件不存在: {}",
            "need_selected_result": "请先选择一个扫描结果。",
            "selected_result": "已选择结果: {}",
            "scan_stopping": "正在请求停止扫描...",
            "scan_stopped": "扫描已停止。",
            "scan_started": "开始扫描目录: {}",
            "scan_preview_done": "扫描预览命中 {} 个文件。",
            "import_dll_count_hint": "如 3、>=5、1-8",
            "none": "- 无",
            "signed_yes": "已签名",
            "signed_no": "未签名",
        },
        "en": {
            "title": "BinarySpy ZeroEye",
            "tools_group": "ZeroEye Tools",
            "scan_group": "Scan Options",
            "results_group": "Scan Results",
            "file": "File",
            "scan_dir": "Scan Dir",
            "output": "Output",
            "browse": "Browse",
            "types": "Types",
            "arch": "Arch",
            "exclude_dll": "Exclude DLL patterns",
            "import_dll_count": "Import DLL count",
            "signed_only": "Signed only",
            "exclude_system_only": "Exclude system-only EXE",
            "analyze": "Analyze File",
            "view_imports": "View Imports",
            "view_exports": "View Exports",
            "scan": "Scan Directory",
            "stop_scan": "Stop Scan",
            "clear_log": "Clear Log",
            "language": "Language",
            "imports_header": "=== Imports ===",
            "exports_header": "=== Exports ===",
            "output_line": "Output: {}",
            "generated_count": "Generated {} result folder(s).",
            "need_scan_dir": "Select a scan directory first",
            "need_file": "Select a target file first",
            "missing_file": "Target file does not exist: {}",
            "need_selected_result": "Select a scan result first.",
            "selected_result": "Selected result: {}",
            "scan_stopping": "Stopping scan...",
            "scan_stopped": "Scan stopped.",
            "scan_started": "Scanning directory: {}",
            "scan_preview_done": "Preview matched {} file(s).",
            "import_dll_count_hint": "e.g. 3, >=5, 1-8",
            "none": "- none",
            "signed_yes": "signed",
            "signed_no": "unsigned",
        },
    }

    def __init__(self, master):
        self.window = ttk.Toplevel(master)
        self.window.geometry("1160x780")
        self.window.transient(master)
        try:
            icon_path = Path.cwd() / "logo.ico"
            if icon_path.exists():
                self.window.iconbitmap(str(icon_path))
        except Exception:
            pass
        self.current_lang = getattr(master, "current_lang", "zh")
        if self.current_lang not in self.LANG:
            self.current_lang = "zh"

        self.analyzer = ZeroEyeAnalyzer(self._append_log)
        self.output_root = tk.StringVar(value=str(Path.cwd()))
        self.file_path = tk.StringVar()
        self.scan_dir = tk.StringVar(value=str(Path.cwd()))
        self.scan_types = tk.StringVar(value="all")
        self.arch_filter = tk.StringVar(value="all")
        self.exclude_patterns = tk.StringVar()
        self.import_dll_count_filter = tk.StringVar()
        self.signed_only = tk.BooleanVar(value=False)
        self.exclude_system_only = tk.BooleanVar(value=False)
        self.lang_var = tk.StringVar(value=self.current_lang)
        self.scan_stop_requested = False
        self.scan_running = False
        self.scan_result_paths: list[str] = []
        self.scan_result_display: list[str] = []

        self._build_ui()
        self._apply_lang()

    def _tr(self, key: str) -> str:
        return self.LANG[self.current_lang][key]

    def _build_ui(self):
        main = ttk.Frame(self.window, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        top_bar = ttk.Frame(main)
        top_bar.pack(fill=tk.X, pady=(0, 6))
        self.lang_lbl = ttk.Label(top_bar, text="")
        self.lang_lbl.pack(side=tk.LEFT)
        self.lang_combo = ttk.Combobox(top_bar, textvariable=self.lang_var, values=["zh", "en"], width=6, state="readonly")
        self.lang_combo.pack(side=tk.LEFT, padx=6)
        self.lang_combo.bind("<<ComboboxSelected>>", lambda _e: self._change_lang())

        self.path_group = ttk.LabelFrame(main, text="", padding=10)
        self.path_group.pack(fill=tk.X, pady=6)
        self.file_lbl = ttk.Label(self.path_group, text="")
        self.file_lbl.grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(self.path_group, textvariable=self.file_path, width=90).grid(row=0, column=1, padx=6, pady=4, sticky=tk.EW)
        self.file_browse_btn = ttk.Button(self.path_group, text="", command=self._browse_file)
        self.file_browse_btn.grid(row=0, column=2, padx=4)
        self.scan_dir_lbl = ttk.Label(self.path_group, text="")
        self.scan_dir_lbl.grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(self.path_group, textvariable=self.scan_dir, width=90).grid(row=1, column=1, padx=6, pady=4, sticky=tk.EW)
        self.scan_dir_browse_btn = ttk.Button(self.path_group, text="", command=self._browse_dir)
        self.scan_dir_browse_btn.grid(row=1, column=2, padx=4)
        self.output_lbl = ttk.Label(self.path_group, text="")
        self.output_lbl.grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(self.path_group, textvariable=self.output_root, width=90).grid(row=2, column=1, padx=6, pady=4, sticky=tk.EW)
        self.output_browse_btn = ttk.Button(self.path_group, text="", command=self._browse_output)
        self.output_browse_btn.grid(row=2, column=2, padx=4)
        self.path_group.columnconfigure(1, weight=1)

        self.option_group = ttk.LabelFrame(main, text="", padding=10)
        self.option_group.pack(fill=tk.X, pady=6)
        self.types_lbl = ttk.Label(self.option_group, text="")
        self.types_lbl.grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(self.option_group, textvariable=self.scan_types, width=18).grid(row=0, column=1, padx=6, pady=4, sticky=tk.W)
        self.arch_lbl = ttk.Label(self.option_group, text="")
        self.arch_lbl.grid(row=0, column=2, sticky=tk.W)
        ttk.Combobox(self.option_group, textvariable=self.arch_filter, values=["all", "x64", "x86"], width=10, state="readonly").grid(row=0, column=3, padx=6, pady=4, sticky=tk.W)
        self.exclude_dll_lbl = ttk.Label(self.option_group, text="")
        self.exclude_dll_lbl.grid(row=0, column=4, sticky=tk.W)
        ttk.Entry(self.option_group, textvariable=self.exclude_patterns, width=18).grid(row=0, column=5, padx=6, pady=4, sticky=tk.W)
        self.import_dll_count_lbl = ttk.Label(self.option_group, text="")
        self.import_dll_count_lbl.grid(row=1, column=0, sticky=tk.W)
        self.import_dll_count_entry = ttk.Entry(self.option_group, textvariable=self.import_dll_count_filter, width=18)
        self.import_dll_count_entry.grid(row=1, column=1, padx=6, pady=4, sticky=tk.W)
        self.signed_only_cb = ttk.Checkbutton(self.option_group, text="", variable=self.signed_only)
        self.signed_only_cb.grid(row=1, column=2, columnspan=2, sticky=tk.W)
        self.exclude_system_cb = ttk.Checkbutton(self.option_group, text="", variable=self.exclude_system_only)
        self.exclude_system_cb.grid(row=1, column=4, columnspan=2, sticky=tk.W)

        action_group = ttk.Frame(main)
        action_group.pack(fill=tk.X, pady=6)
        action_group.columnconfigure(0, weight=1)
        self.analyze_btn = ttk.Button(action_group, text="", command=lambda: self._run_async(self._analyze_file))
        self.analyze_btn.pack(side=tk.LEFT, padx=4)
        self.view_imports_btn = ttk.Button(action_group, text="", command=lambda: self._run_async(self._view_imports))
        self.view_imports_btn.pack(side=tk.LEFT, padx=4)
        self.view_exports_btn = ttk.Button(action_group, text="", command=lambda: self._run_async(self._view_exports))
        self.view_exports_btn.pack(side=tk.LEFT, padx=4)
        self.scan_btn = ttk.Button(action_group, text="", command=lambda: self._run_async(self._scan_directory))
        self.scan_btn.pack(side=tk.LEFT, padx=4)
        self.stop_scan_btn = ttk.Button(action_group, text="", command=self._stop_scan, state=tk.DISABLED)
        self.stop_scan_btn.pack(side=tk.LEFT, padx=4)
        self.clear_btn = ttk.Button(action_group, text="", command=self._clear_log)
        self.clear_btn.pack(side=tk.RIGHT, padx=4)

        self.results_group = ttk.LabelFrame(main, text="", padding=8)
        self.results_group.pack(fill=tk.BOTH, expand=False, pady=(0, 8))
        self.results_list = tk.Listbox(self.results_group, height=9, bg="#0f1319", fg="#d9f8e3", selectbackground="#285577")
        self.results_list.pack(fill=tk.BOTH, expand=True)
        self.results_list.bind("<Double-Button-1>", lambda _e: self._use_selected_result())

        self.log_text = tk.Text(main, height=28, bg="#10151d", fg="#d9f8e3", insertbackground="#d9f8e3")
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=8)

    def _browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("PE files", "*.exe *.dll *.sys"), ("All files", "*.*")])
        if path:
            self.file_path.set(path)

    def _browse_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.scan_dir.set(path)

    def _browse_output(self):
        path = filedialog.askdirectory()
        if path:
            self.output_root.set(path)

    def _change_lang(self):
        self.current_lang = self.lang_var.get()
        if self.current_lang not in self.LANG:
            self.current_lang = "zh"
        self._apply_lang()

    def _apply_lang(self):
        self.window.title(self._tr("title"))
        self.lang_lbl.config(text=self._tr("language"))
        self.path_group.config(text=self._tr("tools_group"))
        self.option_group.config(text=self._tr("scan_group"))
        self.results_group.config(text=self._tr("results_group"))
        self.file_lbl.config(text=self._tr("file"))
        self.scan_dir_lbl.config(text=self._tr("scan_dir"))
        self.output_lbl.config(text=self._tr("output"))
        self.file_browse_btn.config(text=self._tr("browse"))
        self.scan_dir_browse_btn.config(text=self._tr("browse"))
        self.output_browse_btn.config(text=self._tr("browse"))
        self.types_lbl.config(text=self._tr("types"))
        self.arch_lbl.config(text=self._tr("arch"))
        self.exclude_dll_lbl.config(text=self._tr("exclude_dll"))
        self.import_dll_count_lbl.config(text=f"{self._tr('import_dll_count')} ({self._tr('import_dll_count_hint')})")
        self.signed_only_cb.config(text=self._tr("signed_only"))
        self.exclude_system_cb.config(text=self._tr("exclude_system_only"))
        self.analyze_btn.config(text=self._tr("analyze"))
        self.view_imports_btn.config(text=self._tr("view_imports"))
        self.view_exports_btn.config(text=self._tr("view_exports"))
        self.scan_btn.config(text=self._tr("scan"))
        self.stop_scan_btn.config(text=self._tr("stop_scan"))
        self.clear_btn.config(text=self._tr("clear_log"))

    def _append_log(self, message: str):
        self.window.after(0, lambda: self._append_log_ui(message))

    def _append_log_ui(self, message: str):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def _clear_log(self):
        self.log_text.delete("1.0", tk.END)

    def _format_result_row(self, result: AnalysisResult) -> str:
        signed_text = self._tr("signed_yes") if result.signed else self._tr("signed_no")
        return f"[{result.file_kind}/{result.arch}/{signed_text}/dlls={len(result.imports)}] {result.path}"

    def _set_scan_results(self, rows: list[tuple[str, str]]):
        self.scan_result_paths = [path for _, path in rows]
        self.scan_result_display = [label for label, _ in rows]
        self.results_list.delete(0, tk.END)
        for label in self.scan_result_display:
            self.results_list.insert(tk.END, label)

    def _use_selected_result(self):
        selection = self.results_list.curselection()
        if not selection:
            return
        path = self.scan_result_paths[selection[0]]
        self.file_path.set(path)
        self._append_log(self._tr("selected_result").format(path))

    def _stop_scan(self):
        if not self.scan_running:
            return
        self.scan_stop_requested = True
        self._append_log(self._tr("scan_stopping"))

    def _run_async(self, func: Callable[[], None]):
        threading.Thread(target=self._guard, args=(func,), daemon=True).start()

    def _guard(self, func: Callable[[], None]):
        try:
            func()
        except Exception as exc:
            self._append_log(f"[X] {exc}")

    def _analyze_file(self):
        result = self.analyzer.analyze_file(self._require_file())
        for line in self.analyzer.summarize_result(result):
            self._append_log(line)
        self._append_log("")

    def _view_imports(self):
        self._append_log(self._tr("imports_header"))
        for line in self.analyzer.list_imports(self._require_file()):
            self._append_log(line)
        self._append_log("")

    def _view_exports(self):
        self._append_log(self._tr("exports_header"))
        for line in self.analyzer.list_exports(self._require_file()):
            self._append_log(line)
        self._append_log("")

    def _scan_directory(self):
        root = self.scan_dir.get().strip()
        if not root:
            raise ValueError(self._tr("need_scan_dir"))
        self.scan_stop_requested = False
        self.scan_running = True
        self.window.after(0, lambda: self._set_scan_results([]))
        self.window.after(0, lambda: self.stop_scan_btn.config(state=tk.NORMAL))
        self._append_log(self._tr("scan_started").format(root))
        try:
            preview_rows = []
            types = normalize_scan_types(self.scan_types.get())
            patterns = [p.strip().lower() for p in self.exclude_patterns.get().split("|") if p.strip()]
            scan_root = Path(root)
            for path in scan_root.rglob("*"):
                if self.scan_stop_requested:
                    break
                if not path.is_file() or path.suffix.lower() not in {".exe", ".dll", ".sys"}:
                    continue
                result = self.analyzer.analyze_file(path)
                if not result.valid_pe:
                    continue
                if self.arch_filter.get() in {"x64", "64"} and result.arch != "x64":
                    continue
                if self.arch_filter.get() in {"x86", "86"} and result.arch != "x86":
                    continue
                if self.signed_only.get() and not result.signed:
                    continue
                if patterns and any(p in path.name.lower() for p in patterns):
                    continue
                if not self.analyzer._matches_scan_types(result, types):
                    continue
                if not match_numeric_filter(len(result.imports), self.import_dll_count_filter.get()):
                    continue
                if self.exclude_system_only.get() and result.file_kind in {"gui", "cmd", "exe"} and self.analyzer._only_system_imports(result):
                    continue
                preview_rows.append((self._format_result_row(result), str(path)))
            self.window.after(0, lambda rows=preview_rows: self._set_scan_results(rows))
            self._append_log(self._tr("scan_preview_done").format(len(preview_rows)))

            outputs = self.analyzer.scan_directory(
                root_dir=root,
                output_root=self.output_root.get(),
                scan_types=self.scan_types.get(),
                signed_only=self.signed_only.get(),
                arch_filter=self.arch_filter.get(),
                exclude_patterns=self.exclude_patterns.get(),
                exclude_system_only=self.exclude_system_only.get(),
                import_dll_count_filter=self.import_dll_count_filter.get(),
                should_stop=lambda: self.scan_stop_requested,
            )
            if self.scan_stop_requested:
                self._append_log(self._tr("scan_stopped"))
            self._append_log(self._tr("generated_count").format(len(outputs)))
            for item in outputs:
                self._append_log(str(item))
            self._append_log("")
        finally:
            self.scan_running = False
            self.scan_stop_requested = False
            self.window.after(0, lambda: self.stop_scan_btn.config(state=tk.DISABLED))

    def _require_file(self) -> str:
        target = self.file_path.get().strip()
        if not target:
            raise ValueError(self._tr("need_file"))
        if not Path(target).exists():
            raise FileNotFoundError(self._tr("missing_file").format(target))
        return target

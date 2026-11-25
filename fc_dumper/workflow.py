"""End-to-end PlayTogether-style workflow for FC Mobile / Native Android packages."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Callable
import uuid

from .arm64_xref import scan_arm64_string_xrefs
from .dex_analyzer import DexSummary, analyze_dex_files
from .elf_native import load_native_elf
from .exporters import (
    write_assets_json,
    write_dump_cpp_hpp,
    write_functions_json,
    write_ghidra_script,
    write_ida_script,
    write_jni_json,
    write_rtti_json,
    write_strings_json,
)
from .package_extractor import SUPPORTED_EXTS, extract_package_contents
from .rtti_analyzer import analyze_cpp_rtti_and_vtables


APP_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_ROOT = APP_ROOT / "Output"
LogCallback = Callable[[str], None]


@dataclass
class FcDumpConfig:
    target_abi: str = "arm64-v8a"
    target_lib_pattern: str = "libFIFAMobileNeon.so"
    dump_symbols: bool = True
    dump_eh_frame_functions: bool = True
    dump_cpp_rtti: bool = True
    dump_vtables: bool = True
    dump_string_xrefs: bool = True
    dump_java_dex_native: bool = True
    extract_all_so: bool = False
    extract_dex: bool = True
    extract_assets: bool = False
    generate_ida_scripts: bool = True
    generate_ghidra_scripts: bool = True
    generate_cpp_header_dump: bool = True


@dataclass
class FcWorkflowResult:
    package_path: Path
    output_dir: Path
    input_dir: Path
    primary_so_path: Path
    primary_so_sha256: str
    dump_cpp_path: Path | None = None
    rtti_json_path: Path | None = None
    functions_json_path: Path | None = None
    strings_json_path: Path | None = None
    jni_json_path: Path | None = None
    assets_json_path: Path | None = None
    ida_script_path: Path | None = None
    ghidra_script_path: Path | None = None
    result_json_path: Path | None = None
    log_path: Path | None = None
    package_id: str = ""
    version_name: str = ""
    eh_function_count: int = 0
    symbol_count: int = 0
    rtti_class_count: int = 0
    haxe_class_count: int = 0
    vtable_count: int = 0
    vfunc_slot_count: int = 0
    string_xref_count: int = 0
    dex_native_count: int = 0
    matched_jni_count: int = 0
    asset_count: int = 0
    elapsed_seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)


def load_config(config_path: Path | None = None) -> FcDumpConfig:
    """Load config.json from workspace root or explicit path."""
    cand = config_path or (APP_ROOT / "config.json")
    raw: dict[str, object] = {}
    if cand.is_file():
        try:
            loaded = json.loads(cand.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                raw = loaded
        except Exception:
            pass
    return FcDumpConfig(
        target_abi=str(raw.get("TargetAbi", "arm64-v8a")),
        target_lib_pattern=str(raw.get("TargetLibPattern", "libFIFAMobileNeon.so")),
        dump_symbols=bool(raw.get("DumpSymbols", True)),
        dump_eh_frame_functions=bool(raw.get("DumpEhFrameFunctions", True)),
        dump_cpp_rtti=bool(raw.get("DumpCppRtti", True)),
        dump_vtables=bool(raw.get("DumpVtables", True)),
        dump_string_xrefs=bool(raw.get("DumpStringXrefs", True)),
        dump_java_dex_native=bool(raw.get("DumpJavaDexNative", True)),
        extract_all_so=bool(raw.get("ExtractAllSo", False)),
        extract_dex=bool(raw.get("ExtractDex", True)),
        extract_assets=bool(raw.get("ExtractAssets", False)),
        generate_ida_scripts=bool(raw.get("GenerateIdaScripts", True)),
        generate_ghidra_scripts=bool(raw.get("GenerateGhidraScripts", True)),
        generate_cpp_header_dump=bool(raw.get("GenerateCppHeaderDump", True)),
    )


def _sanitize_path_part(value: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", value.strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("._ ")
    return cleaned or "package"


def create_run_directory(package_path: Path, output_root: Path | None = None) -> Path:
    root = (output_root or DEFAULT_OUTPUT_ROOT).resolve()
    root.mkdir(parents=True, exist_ok=True)
    stem = _sanitize_path_part(package_path.stem)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = uuid.uuid4().hex[:6]
    run_dir = root / f"{stem}_{stamp}_{suffix}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def find_default_package(search_dirs: Path | str | list[Path] | None = None) -> Path | None:
    """Auto-locate an FC Mobile / native `.xapk`/`.apk` package."""
    if search_dirs is None:
        roots = [APP_ROOT, APP_ROOT.parent, Path.home() / "Downloads"]
    elif isinstance(search_dirs, (str, Path)):
        roots = [Path(search_dirs)]
    else:
        roots = list(search_dirs)

    seen: set[Path] = set()
    candidates: list[Path] = []
    for root in roots:
        if not root or not root.is_dir():
            continue
        for pat in ("*.xapk", "*.apks", "*.apk"):
            for p in root.glob(pat):
                rp = p.resolve()
                if rp.is_file() and rp not in seen:
                    seen.add(rp)
                    candidates.append(rp)
    if not candidates:
        return None

    def _score(p: Path) -> tuple[int, int]:
        name = p.name.lower()
        prio = 2
        if "fc" in name or "fifa" in name or "fcmobile" in name:
            prio = 0
        elif p.suffix.lower() == ".xapk":
            prio = 1
        return (prio, -p.stat().st_size)

    candidates.sort(key=_score)
    return candidates[0]


def run_fc_dump(
    package_path: str | Path,
    output_root: str | Path | None = None,
    config_path: str | Path | None = None,
    config: FcDumpConfig | None = None,
    log: LogCallback | None = None,
) -> FcWorkflowResult:
    """Extract native ELF/DEX/assets and dump RTTI, vtables, `.eh_frame`, XREFs & IDA/Ghidra scripts."""
    t_start = time.perf_counter()
    pkg = Path(package_path).resolve()
    if not pkg.is_file():
        raise FileNotFoundError(f"Không tìm thấy file package: {pkg}")
    if pkg.suffix.lower() not in SUPPORTED_EXTS:
        raise ValueError(f"Định dạng không hỗ trợ ({pkg.suffix}). Chọn .xapk, .apks, .apk hoặc .zip.")

    cfg = config or load_config(Path(config_path) if config_path else None)
    run_dir = create_run_directory(pkg, Path(output_root) if output_root else DEFAULT_OUTPUT_ROOT)
    input_dir = run_dir / "Input"
    input_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "dump.log"
    log_lines: list[str] = []

    def emit(message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        log_lines.append(f"[{stamp}] {message}")
        if log is not None:
            log(message)

    try:
        emit(f"Bắt đầu dump FC Native: {pkg.name}")
        emit(f"Thư mục kết quả: {run_dir}")

        emit("[1/5] Trích xuất nhị phân native (.so), DEX & phân loại assets...")
        assets_dir = (run_dir / "Assets") if cfg.extract_assets else None
        ext = extract_package_contents(
            pkg,
            target_abi=cfg.target_abi,
            target_lib_pattern=cfg.target_lib_pattern,
            extract_all_so=cfg.extract_all_so,
            extract_dex=cfg.extract_dex,
            assets_out_dir=assets_dir,
        )
        for name, data in ext.all_so_files.items():
            (input_dir / name).write_bytes(data)
        if cfg.extract_dex:
            dex_dir = input_dir / "dex"
            dex_dir.mkdir(parents=True, exist_ok=True)
            for d_name, d_bytes in ext.dex_files.items():
                (dex_dir / d_name).write_bytes(d_bytes)

        primary_so_path = input_dir / ext.primary_so_name
        so_sha256 = hashlib.sha256(ext.primary_so_bytes).hexdigest()
        emit(
            f"  + Thư viện chính: {ext.primary_so_name} ({len(ext.primary_so_bytes):,} bytes) | "
            f"{len(ext.dex_files)} DEX | {len(ext.assets_index):,} assets"
        )

        emit("[2/5] Nạp ELF, áp dụng .rela.dyn & quét .eh_frame...")
        elf = load_native_elf(
            ext.primary_so_bytes,
            log=emit,
            parse_eh_frame=cfg.dump_eh_frame_functions,
        )

        emit("[3/5] Giải mã C++ RTTI (`type_info`), cây kế thừa & VTables...")
        if cfg.dump_cpp_rtti:
            rtti = analyze_cpp_rtti_and_vtables(elf)
        else:
            from .rtti_analyzer import RttiAnalysisResult

            rtti = RttiAnalysisResult()
        emit(
            f"  + Đã khôi phục {len(rtti.classes):,} RTTI classes "
            f"({rtti.haxe_class_count:,} Haxe/hxcpp), {rtti.total_vtables:,} vtables, "
            f"{rtti.total_vfunc_slots:,} virtual slots"
        )

        emit("[4/5] Quét ARM64 XREF chuỗi C++/.proto/Haxe & đối chiếu Java JNI...")
        if cfg.dump_string_xrefs:
            xref = scan_arm64_string_xrefs(elf)
        else:
            from .arm64_xref import XrefAnalysisResult

            xref = XrefAnalysisResult()
        xref_hits = sum(1 for s in xref.strings if s.func_vas)
        emit(
            f"  + Thu được {len(xref.strings):,} chuỗi phân loại "
            f"({xref_hits:,} có XREF vào {len(xref.func_strings):,} hàm)"
        )

        if cfg.dump_java_dex_native and ext.dex_files:
            dex_summary = analyze_dex_files(sorted(ext.dex_files.items()), elf=elf)
        else:
            dex_summary = DexSummary()
        matched_jni = sum(1 for m in dex_summary.native_methods if m.matched_elf_va > 0)
        emit(
            f"  + DEX: {dex_summary.total_classes:,} classes, {dex_summary.total_methods:,} methods, "
            f"{len(dex_summary.native_methods)} native ({matched_jni} khớp Java_* trong ELF)"
        )

        emit("[5/5] Xuất dump_cpp.hpp, JSON & script IDA/Ghidra...")
        dump_cpp_path = (
            write_dump_cpp_hpp(run_dir / "dump_cpp.hpp", ext.primary_so_name, elf, rtti, xref)
            if cfg.generate_cpp_header_dump
            else None
        )
        rtti_json_path = write_rtti_json(run_dir / "rtti_classes.json", rtti)
        functions_json_path = write_functions_json(run_dir / "functions.json", elf, rtti, xref)
        strings_json_path = write_strings_json(run_dir / "strings_cpp.json", xref)
        jni_json_path = write_jni_json(run_dir / "jni_bridge.json", dex_summary)
        assets_json_path = write_assets_json(run_dir / "assets_index.json", ext.assets_index)

        ida_script_path = (
            write_ida_script(run_dir / "ida_fc_symbols.py", elf, rtti, xref)
            if cfg.generate_ida_scripts
            else None
        )
        ghidra_script_path = (
            write_ghidra_script(run_dir / "ghidra_fc_symbols.py", elf, rtti, xref)
            if cfg.generate_ghidra_scripts
            else None
        )

        elapsed = time.perf_counter() - t_start
        result_payload = {
            "package": str(pkg),
            "packageId": ext.package_name,
            "versionName": ext.version_name,
            "versionCode": ext.version_code,
            "primaryLibrary": ext.primary_so_name,
            "primaryLibrarySha256": so_sha256,
            "machine": elf.machine,
            "symbols": len(elf.symbols),
            "ehFrameFunctions": len(elf.eh_functions),
            "rttiClasses": len(rtti.classes),
            "haxeClasses": rtti.haxe_class_count,
            "vtables": rtti.total_vtables,
            "vfuncSlots": rtti.total_vfunc_slots,
            "stringsClassified": len(xref.strings),
            "stringsWithXref": xref_hits,
            "dexClasses": dex_summary.total_classes,
            "dexNativeMethods": len(dex_summary.native_methods),
            "matchedJniExports": matched_jni,
            "assetsIndexed": len(ext.assets_index),
            "assetsExtracted": ext.extracted_asset_count,
            "elapsedSeconds": round(elapsed, 2),
        }
        result_json_path = run_dir / "result.json"
        result_json_path.write_text(json.dumps(result_payload, indent=2, ensure_ascii=False), encoding="utf-8")
        emit(
            f"Hoàn tất dump trong {elapsed:.2f}s! "
            f"({len(elf.eh_functions):,} hàm, {len(rtti.classes):,} RTTI classes, {rtti.total_vtables:,} vtables)"
        )
        return FcWorkflowResult(
            package_path=pkg,
            output_dir=run_dir,
            input_dir=input_dir,
            primary_so_path=primary_so_path,
            primary_so_sha256=so_sha256,
            dump_cpp_path=dump_cpp_path,
            rtti_json_path=rtti_json_path,
            functions_json_path=functions_json_path,
            strings_json_path=strings_json_path,
            jni_json_path=jni_json_path,
            assets_json_path=assets_json_path,
            ida_script_path=ida_script_path,
            ghidra_script_path=ghidra_script_path,
            result_json_path=result_json_path,
            log_path=log_path,
            package_id=ext.package_name,
            version_name=ext.version_name,
            eh_function_count=len(elf.eh_functions),
            symbol_count=len(elf.symbols),
            rtti_class_count=len(rtti.classes),
            haxe_class_count=rtti.haxe_class_count,
            vtable_count=rtti.total_vtables,
            vfunc_slot_count=rtti.total_vfunc_slots,
            string_xref_count=xref_hits,
            dex_native_count=len(dex_summary.native_methods),
            matched_jni_count=matched_jni,
            asset_count=len(ext.assets_index),
            elapsed_seconds=elapsed,
        )
    finally:
        if log_lines:
            try:
                log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
            except OSError:
                pass

"""Output exporters for FC Mobile Native ELF / RTTI / VTable / XREF / JNI / Asset dumps."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re

from .arm64_xref import XrefAnalysisResult
from .dex_analyzer import DexSummary
from .elf_native import NativeElfImage
from .package_extractor import AssetEntryInfo
from .rtti_analyzer import RttiAnalysisResult


def _ida_ident(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_:]", "_", name)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    if not cleaned or cleaned[0].isdigit():
        cleaned = "fn_" + cleaned
    return cleaned[:120]


def write_dump_cpp_hpp(
    out_path: Path,
    lib_name: str,
    image: NativeElfImage,
    rtti: RttiAnalysisResult,
    xref: XrefAnalysisResult,
) -> Path:
    """Emit searchable `dump_cpp.hpp` summarizing exports, RTTI hierarchy, vtables, and virtual methods."""
    lines: list[str] = [
        "// ============================================================================",
        f"// FC Mobile / Native C++ & Haxe (hxcpp) Static Dump",
        f"// Binary: {lib_name} ({image.machine}, {'ELF64' if image.is_64 else 'ELF32'})",
        f"// .eh_frame functions : {len(image.eh_functions):,}",
        f"// RTTI classes        : {len(rtti.classes):,} (Haxe/hxcpp: {rtti.haxe_class_count:,})",
        f"// VTables / VFuncs    : {rtti.total_vtables:,} / {rtti.total_vfunc_slots:,}",
        f"// String XREFs        : {sum(1 for s in xref.strings if s.func_vas):,}",
        "// ============================================================================",
        "",
    ]

    jni_syms = sorted((s for s in image.symbols if s.value > 0 and s.name.startswith("Java_")), key=lambda s: s.name)
    if jni_syms:
        lines.append(f"// --- JNI Native Exports ({len(jni_syms)}) ---")
        for sym in jni_syms:
            lines.append(f"// RVA: 0x{sym.value:X} | Size: 0x{sym.size:X}")
            lines.append(f"extern \"C\" void {sym.name}();")
        lines.append("")

    for cls in rtti.classes:
        base_clause = ""
        if cls.bases:
            base_clause = " : " + ", ".join(
                f"public {b.base_name} /* +0x{b.offset:X} */" if b.offset else f"public {b.base_name}"
                for b in cls.bases
            )
        tag = " [hxcpp]" if cls.is_haxe else ""
        lines.append(f"// TypeInfo: 0x{cls.ti_va:X} | Kind: {cls.kind}{tag} | Mangled: {cls.mangled_name}")
        lines.append(f"class {cls.demangled_name}{base_clause}")
        lines.append("{")
        if not cls.vtables:
            lines.append("    // (No vtable located in .data.rel.ro/.data)")
        for vtbl in cls.vtables:
            lines.append(f"    // VTable RVA: 0x{vtbl.vtable_va:X} (offset_to_top={vtbl.offset_to_top})")
            for slot_idx, f_va in enumerate(vtbl.slots):
                if f_va == 0:
                    lines.append(f"    /* slot {slot_idx:2d} */ virtual void vfunc_{slot_idx}() = 0;")
                else:
                    sym_names = [s.demangled for s in image.symbols_by_va.get(f_va, [])]
                    refs = xref.func_strings.get(f_va, [])
                    note_parts: list[str] = [f"RVA: 0x{f_va:X}"]
                    if sym_names:
                        note_parts.append(f"Sym: {sym_names[0]}")
                    elif f_va in xref.inferred_func_names:
                        note_parts.append(f"Hint: {xref.inferred_func_names[f_va]}")
                    if refs:
                        note_parts.append("Strings: " + "; ".join(repr(r[:48]) for r in refs[:2]))
                    lines.append(f"    /* slot {slot_idx:2d} */ virtual void vfunc_{slot_idx}(); // {' | '.join(note_parts)}")
        lines.append("};")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def write_rtti_json(out_path: Path, rtti: RttiAnalysisResult) -> Path:
    payload = {
        "classCount": len(rtti.classes),
        "haxeClassCount": rtti.haxe_class_count,
        "vtableCount": rtti.total_vtables,
        "vfuncSlotCount": rtti.total_vfunc_slots,
        "classes": [
            {
                "tiVa": f"0x{c.ti_va:X}",
                "kind": c.kind,
                "isHaxe": c.is_haxe,
                "name": c.demangled_name,
                "mangled": c.mangled_name,
                "bases": [
                    {"name": b.base_name, "tiVa": f"0x{b.base_va:X}", "offset": b.offset}
                    for b in c.bases
                ],
                "vtables": [
                    {
                        "vtableVa": f"0x{v.vtable_va:X}",
                        "offsetToTop": v.offset_to_top,
                        "slots": [f"0x{fv:X}" if fv else "0x0" for fv in v.slots],
                    }
                    for v in c.vtables
                ],
            }
            for c in rtti.classes
        ],
    }
    out_path.write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    return out_path


def write_functions_json(
    out_path: Path,
    image: NativeElfImage,
    rtti: RttiAnalysisResult,
    xref: XrefAnalysisResult,
) -> Path:
    entries: list[dict[str, object]] = []
    seen_va: set[int] = set()

    for f in image.eh_functions:
        seen_va.add(f.va)
        syms = image.symbols_by_va.get(f.va, [])
        owners = rtti.vfunc_owners.get(f.va, [])
        item: dict[str, object] = {
            "va": f"0x{f.va:X}",
            "size": f.size,
        }
        if syms:
            item["symbol"] = syms[0].name
            if syms[0].demangled != syms[0].name:
                item["demangled"] = syms[0].demangled
        elif f.va in xref.inferred_func_names:
            item["hint"] = xref.inferred_func_names[f.va]
        if owners:
            item["vfunc"] = f"{owners[0][0]}::slot_{owners[0][2]}" + (
                f" (+{len(owners) - 1} shared)" if len(owners) > 1 else ""
            )
        refs = xref.func_strings.get(f.va)
        if refs:
            item["strings"] = refs
        entries.append(item)

    # Also include exported FUNC symbols not already listed in .eh_frame
    for sym in image.symbols:
        if sym.value > 0 and sym.sym_type == "FUNC" and sym.value not in seen_va:
            seen_va.add(sym.value)
            entries.append(
                {
                    "va": f"0x{sym.value:X}",
                    "size": sym.size,
                    "symbol": sym.name,
                    "demangled": sym.demangled,
                }
            )

    payload = {"count": len(entries), "functions": entries}
    out_path.write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    return out_path


def write_strings_json(out_path: Path, xref: XrefAnalysisResult) -> Path:
    payload = {
        "count": len(xref.strings),
        "withXrefCount": sum(1 for s in xref.strings if s.func_vas),
        "strings": [
            {
                "va": f"0x{s.va:X}",
                "category": s.category,
                "value": s.value,
                "funcVas": [f"0x{fv:X}" for fv in s.func_vas[:32]],
            }
            for s in xref.strings
        ],
    }
    out_path.write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    return out_path


def write_jni_json(out_path: Path, dex_summary: DexSummary) -> Path:
    matched = sum(1 for m in dex_summary.native_methods if m.matched_elf_va > 0)
    payload = {
        "dexFiles": dex_summary.dex_files,
        "totalDexClasses": dex_summary.total_classes,
        "totalDexMethods": dex_summary.total_methods,
        "nativeMethodCount": len(dex_summary.native_methods),
        "matchedNativeToElfCount": matched,
        "eaGarenaPackages": dex_summary.ea_garena_packages,
        "nativeMethods": [
            {
                "dexFile": m.dex_file,
                "javaClass": m.java_class,
                "method": m.method_name,
                "signature": f"{m.return_type} {m.method_name}({', '.join(m.param_types)})",
                "isStatic": m.is_static,
                "jniExpectedSymbol": m.jni_c_name,
                "matchedElfSymbol": m.matched_elf_symbol,
                "matchedElfVa": f"0x{m.matched_elf_va:X}" if m.matched_elf_va else "",
            }
            for m in dex_summary.native_methods
        ],
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def write_assets_json(out_path: Path, assets: list[AssetEntryInfo]) -> Path:
    by_kind = Counter(a.kind for a in assets)
    payload = {
        "totalAssets": len(assets),
        "countsByKind": dict(by_kind.most_common()),
        "assets": [
            {
                "sourceApk": a.source_apk,
                "path": a.zip_path,
                "size": a.size,
                "kind": a.kind,
                "guessedExt": a.guessed_ext,
                "magicHex": a.magic_hex,
            }
            for a in assets
        ],
    }
    out_path.write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    return out_path


def _collect_symbol_assignments(
    image: NativeElfImage,
    rtti: RttiAnalysisResult,
    xref: XrefAnalysisResult,
) -> tuple[list[tuple[int, str]], list[tuple[int, str]], list[tuple[int, str]]]:
    """Build de-duplicated (va, name) lists for functions, data labels (RTTI/vtables), and comments."""
    used_names: set[str] = set()
    func_labels: list[tuple[int, str]] = []
    data_labels: list[tuple[int, str]] = []
    comments: list[tuple[int, str]] = []
    assigned_func_vas: set[int] = set()

    def unique_name(base: str, va: int) -> str:
        ident = _ida_ident(base)
        if ident not in used_names:
            used_names.add(ident)
            return ident
        cand = f"{ident}_{va:X}"
        used_names.add(cand)
        return cand

    # 1. Explicit ELF symbols (.dynsym/.symtab)
    for sym in image.symbols:
        if sym.value <= 0 or not sym.name:
            continue
        name = unique_name(sym.name, sym.value)
        if sym.sym_type == "FUNC":
            if sym.value not in assigned_func_vas:
                assigned_func_vas.add(sym.value)
                func_labels.append((sym.value, name))
        else:
            data_labels.append((sym.value, name))

    # 2. RTTI typeinfo & vtable labels
    for cls in rtti.classes:
        data_labels.append((cls.ti_va, unique_name(f"RTTI_{cls.demangled_name}", cls.ti_va)))
        for vi, vtbl in enumerate(cls.vtables):
            suffix = "" if vi == 0 else f"_{vi}"
            data_labels.append(
                (vtbl.vtable_va, unique_name(f"vtable_{cls.demangled_name}{suffix}", vtbl.vtable_va))
            )

    # 3. Single-owner virtual functions from vtables
    for fva, owners in rtti.vfunc_owners.items():
        if fva in assigned_func_vas:
            continue
        if len(owners) == 1:
            cls_name, _vtbl_va, slot_idx = owners[0]
            assigned_func_vas.add(fva)
            func_labels.append((fva, unique_name(f"{cls_name}::vfunc_{slot_idx}", fva)))
        else:
            comments.append((fva, f"Shared virtual slot ({len(owners)} classes), e.g. {owners[0][0]}::vfunc_{owners[0][2]}"))

    # 4. Unique C++ string XREF function hints
    for fva, hint in xref.inferred_func_names.items():
        if fva not in assigned_func_vas:
            assigned_func_vas.add(fva)
            func_labels.append((fva, unique_name(hint, fva)))

    for fva, strs in xref.func_strings.items():
        comments.append((fva, "Strings: " + " | ".join(s[:60] for s in strs[:3])))

    return func_labels, data_labels, comments


def write_ida_script(
    out_path: Path,
    image: NativeElfImage,
    rtti: RttiAnalysisResult,
    xref: XrefAnalysisResult,
) -> Path:
    """Write Python 2/3 IDA Pro script applying `.eh_frame` functions, exports, RTTI, vtables, and comments."""
    func_labels, data_labels, comments = _collect_symbol_assignments(image, rtti, xref)

    payload = {
        "ehFunctions": [[f.va, f.va + f.size] for f in image.eh_functions if f.size > 0],
        "funcLabels": [[va, name] for va, name in func_labels],
        "dataLabels": [[va, name] for va, name in data_labels],
        "comments": [[va, text] for va, text in comments],
    }
    data_path = out_path.with_suffix(".json")
    data_path.write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")

    script = f'''# -*- coding: utf-8 -*-
# IDA Pro 7+/8+/9+ script (Python 2 & Python 3) generated by FC Dumper
import json
import os
import idaapi
import ida_funcs
import ida_name
import idc

BASE = idaapi.get_imagebase()
JSON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "{data_path.name}")

def main():
    with open(JSON_PATH, "r") as f:
        data = json.load(f)

    created = 0
    for start_rva, end_rva in data.get("ehFunctions", []):
        ea = BASE + start_rva
        if ida_funcs.get_func(ea) is None:
            if ida_funcs.add_func(ea, BASE + end_rva):
                created += 1

    renamed = 0
    for rva, name in data.get("funcLabels", []):
        ea = BASE + rva
        if ida_funcs.get_func(ea) is None:
            ida_funcs.add_func(ea)
        if ida_name.set_name(ea, str(name), ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
            renamed += 1

    for rva, name in data.get("dataLabels", []):
        ida_name.set_name(BASE + rva, str(name), ida_name.SN_NOWARN | ida_name.SN_NOCHECK)

    for rva, cmt in data.get("comments", []):
        idc.set_cmt(BASE + rva, str(cmt), 1)

    print("[FC Dumper] Created funcs: %d | Named funcs/labels: %d" % (created, renamed))

if __name__ == "__main__":
    main()
'''
    out_path.write_text(script, encoding="utf-8")
    return out_path


def write_ghidra_script(
    out_path: Path,
    image: NativeElfImage,
    rtti: RttiAnalysisResult,
    xref: XrefAnalysisResult,
) -> Path:
    """Write Ghidra Python script consuming `ida_fc_symbols.json` symbols & comments."""
    script = '''# Ghidra Python script generated by FC Dumper
# Place alongside ida_fc_symbols.json and run from Ghidra Script Manager.
import json
import os

from ghidra.program.model.symbol import SourceType

def main():
    base = currentProgram.getImageBase().getOffset()
    json_path = os.path.join(os.path.dirname(sourceFile.getAbsolutePath()), "ida_fc_symbols.json")
    with open(json_path, "r") as f:
        data = json.load(f)

    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    created = 0
    named = 0

    for start_rva, _end_rva in data.get("ehFunctions", []):
        addr = toAddr(base + start_rva)
        if fm.getFunctionAt(addr) is None:
            if createFunction(addr, None) is not None:
                created += 1

    for rva, name in data.get("funcLabels", []):
        addr = toAddr(base + rva)
        fn = fm.getFunctionAt(addr) or createFunction(addr, name)
        if fn is not None:
            fn.setName(name, SourceType.USER_DEFINED)
            named += 1
        else:
            createLabel(addr, name, True)

    for rva, name in data.get("dataLabels", []):
        createLabel(toAddr(base + rva), name, True)

    for rva, cmt in data.get("comments", []):
        cu = listing.getCodeUnitAt(toAddr(base + rva))
        if cu is not None:
            cu.setComment(cu.EOL_COMMENT, cmt)

    print("[FC Dumper] Ghidra created funcs: %d | named: %d" % (created, named))

main()
'''
    out_path.write_text(script, encoding="utf-8")
    return out_path

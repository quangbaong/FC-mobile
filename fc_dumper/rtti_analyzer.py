"""C++ Itanium RTTI (`type_info` + inheritance) & VTable analyzer for relocated ELF binaries."""

from __future__ import annotations

from dataclasses import dataclass, field
import struct

from .elf_native import NativeElfImage
from .itanium_demangler import demangle_rtti_name


@dataclass
class RttiBaseInfo:
    base_va: int
    base_name: str
    offset: int


@dataclass
class RttiVtableInfo:
    vtable_va: int
    offset_to_top: int
    slots: list[int]  # 0 indicates __cxa_pure_virtual or external stub


@dataclass
class RttiClassRecord:
    ti_va: int
    kind: str  # "class", "si_class", "vmi_class"
    mangled_name: str
    demangled_name: str
    is_haxe: bool
    bases: list[RttiBaseInfo] = field(default_factory=list)
    vtables: list[RttiVtableInfo] = field(default_factory=list)


@dataclass
class RttiAnalysisResult:
    classes: list[RttiClassRecord] = field(default_factory=list)
    by_ti_va: dict[int, RttiClassRecord] = field(default_factory=dict)
    vfunc_owners: dict[int, list[tuple[str, int, int]]] = field(default_factory=dict)  # func_va -> [(cls, vtbl_va, slot)]
    total_vtables: int = 0
    total_vfunc_slots: int = 0
    haxe_class_count: int = 0


def _classify_rtti_vptr(sym_name: str) -> str | None:
    if "17__class_type_infoE" in sym_name:
        return "class"
    if "20__si_class_type_infoE" in sym_name:
        return "si_class"
    if "21__vmi_class_type_infoE" in sym_name:
        return "vmi_class"
    return None


def analyze_cpp_rtti_and_vtables(image: NativeElfImage) -> RttiAnalysisResult:
    """Recover C++ RTTI type_info graph, inheritance, vtables, and virtual functions."""
    result = RttiAnalysisResult()
    if not image.is_64:
        return result

    # 1. Recover all type_info records pointed by ABS64/GLOB_DAT relocations to __cxxabiv1 type_info vtables
    raw_entries: list[tuple[int, str, str, str, list[tuple[int, int]]]] = []
    for ti_va, (sym_name, _) in image.abs64_refs.items():
        kind = _classify_rtti_vptr(sym_name)
        if kind is None:
            continue
        foff = image.va_to_offset(ti_va)
        if foff < 0 or foff + 16 > len(image.buf):
            continue
        name_ptr = struct.unpack_from("<Q", image.buf, foff + 8)[0]
        mangled = image.read_cstr_va(name_ptr, max_len=512)
        if not mangled:
            continue

        base_refs: list[tuple[int, int]] = []
        if kind == "si_class" and foff + 24 <= len(image.buf):
            b_ti = struct.unpack_from("<Q", image.buf, foff + 16)[0]
            if b_ti:
                base_refs.append((b_ti, 0))
        elif kind == "vmi_class" and foff + 24 <= len(image.buf):
            bcnt = struct.unpack_from("<I", image.buf, foff + 20)[0]
            for i in range(min(bcnt, 32)):
                p = foff + 24 + i * 16
                if p + 16 > len(image.buf):
                    break
                b_ti, b_flags = struct.unpack_from("<Qq", image.buf, p)
                if b_ti:
                    base_refs.append((b_ti, b_flags >> 8))

        dem = demangle_rtti_name(mangled)
        raw_entries.append((ti_va, kind, mangled, dem, base_refs))

    # Populate records first so bases resolve cleanly and track all type_info struct slots
    ti_struct_slots: set[int] = set()
    for ti_va, kind, mangled, dem, base_refs in raw_entries:
        is_haxe = dem.endswith("_obj") or dem.startswith(("hx::", "com::ea::fifa::", "madden::"))
        rec = RttiClassRecord(
            ti_va=ti_va,
            kind=kind,
            mangled_name=mangled,
            demangled_name=dem,
            is_haxe=is_haxe,
        )
        result.by_ti_va[ti_va] = rec
        result.classes.append(rec)
        if is_haxe:
            result.haxe_class_count += 1
        struct_words = 2
        if kind == "si_class":
            struct_words = 3
        elif kind == "vmi_class":
            struct_words = 3 + len(base_refs) * 2
        for w_i in range(struct_words):
            ti_struct_slots.add(ti_va + w_i * 8)

    for ti_va, _, _, _, base_refs in raw_entries:
        rec = result.by_ti_va[ti_va]
        for b_ti, off in base_refs:
            b_rec = result.by_ti_va.get(b_ti)
            rec.bases.append(
                RttiBaseInfo(
                    base_va=b_ti,
                    base_name=b_rec.demangled_name if b_rec else f"0x{b_ti:X}",
                    offset=off,
                )
            )

    # 2. Scan .data.rel.ro (and .data) for vtables referencing discovered type_info VAs
    text_sec = image.sections.get(".text")
    t_start = text_sec.addr if text_sec else 0
    t_end = (text_sec.addr + text_sec.size) if text_sec else 0

    for sec_name in (".data.rel.ro", ".data"):
        sec = image.sections.get(sec_name)
        if sec is None or sec.size < 16 or sec.offset + sec.size > len(image.buf):
            continue
        cnt = sec.size // 8
        qwords = struct.unpack_from(f"<{cnt}Q", image.buf, sec.offset)
        for idx, val in enumerate(qwords):
            rec = result.by_ti_va.get(val)
            if rec is None or idx == 0:
                continue
            rtti_slot_va = sec.addr + idx * 8
            if rtti_slot_va in ti_struct_slots:
                continue
            top_slot_va = rtti_slot_va - 8
            if top_slot_va in image.relocated_addrs or top_slot_va in image.abs64_refs:
                continue
            off_to_top = struct.unpack_from("<q", image.buf, sec.offset + (idx - 1) * 8)[0]
            if off_to_top > 0 or off_to_top < -0x100000:
                continue

            vfuncs: list[int] = []
            j = idx + 1
            while j < cnt:
                fv = qwords[j]
                fva = sec.addr + j * 8
                if fv in result.by_ti_va:
                    break
                ext_ref = image.abs64_refs.get(fva)
                if ext_ref is not None:
                    ext_name, _ = ext_ref
                    if "__cxa_pure_virtual" in ext_name:
                        vfuncs.append(0)
                        j += 1
                        continue
                    break
                if t_start <= fv < t_end and (fv & 3) == 0 and (
                    not image.relocated_addrs or fva in image.relocated_addrs
                ):
                    vfuncs.append(fv)
                    j += 1
                else:
                    break

            vtbl_va = rtti_slot_va + 8
            rec.vtables.append(RttiVtableInfo(vtable_va=vtbl_va, offset_to_top=off_to_top, slots=vfuncs))
            result.total_vtables += 1
            result.total_vfunc_slots += len(vfuncs)
            for s_idx, f_va in enumerate(vfuncs):
                if f_va > 0:
                    result.vfunc_owners.setdefault(f_va, []).append((rec.demangled_name, vtbl_va, s_idx))

    result.classes.sort(key=lambda c: c.demangled_name)
    return result

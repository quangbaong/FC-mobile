"""ELF64/ELF32 parser, .rela.dyn patcher, and .eh_frame_hdr/.eh_frame function extractor."""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Callable

from .itanium_demangler import demangle_symbol


ELF_MAGIC = b"\x7fELF"
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNSYM = 11

PT_LOAD = 1
R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027

PT_NAMES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
}

EM_NAMES = {
    40: "ARM",
    62: "x86_64",
    183: "AArch64",
}


@dataclass
class ElfSectionInfo:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int


@dataclass
class ElfSegmentInfo:
    ptype: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass
class ElfSymbolInfo:
    index: int
    name: str
    demangled: str
    value: int
    size: int
    binding: str
    sym_type: str
    shndx: int


@dataclass
class EhFunctionEntry:
    va: int
    size: int
    fde_va: int


@dataclass
class NativeElfImage:
    """In-memory relocated ELF64/ELF32 image ready for RTTI, vtable, .eh_frame and XREF scans."""

    buf: bytearray
    is_64: bool
    machine: str
    segments: list[ElfSegmentInfo]
    sections: dict[str, ElfSectionInfo]
    symbols: list[ElfSymbolInfo]
    symbols_by_idx: dict[int, ElfSymbolInfo]
    symbols_by_va: dict[int, list[ElfSymbolInfo]]
    relocated_addrs: set[int] = field(default_factory=set)
    abs64_refs: dict[int, tuple[str, int]] = field(default_factory=dict)
    eh_functions: list[EhFunctionEntry] = field(default_factory=list)

    def va_to_offset(self, va: int) -> int:
        for seg in self.segments:
            if seg.ptype == PT_LOAD and seg.vaddr <= va < seg.vaddr + seg.filesz:
                return seg.offset + (va - seg.vaddr)
        return -1

    def read_cstr_va(self, va: int, max_len: int = 512) -> str:
        off = self.va_to_offset(va)
        if off < 0 or off >= len(self.buf):
            return ""
        end = self.buf.find(0, off, min(len(self.buf), off + max_len))
        if end < 0:
            end = min(len(self.buf), off + max_len)
        return bytes(self.buf[off:end]).decode("utf-8", errors="replace")


def _read_cstr(data: bytes | bytearray, off: int) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(0, off)
    if end < 0:
        end = len(data)
    return bytes(data[off:end]).decode("utf-8", errors="replace")


def _read_encoded_ptr(buf: bytes | bytearray, pos: int, enc: int, base_va: int) -> tuple[int, int]:
    """Decode DWARF exception header encoded pointer (`enc & 0x0f`, `enc & 0x70`)."""
    if enc == 0xFF:  # DW_EH_PE_omit
        return 0, pos
    fmt = enc & 0x0F
    rel = enc & 0x70
    if fmt in (0x01,):  # uleb128
        val = 0
        shift = 0
        while pos < len(buf):
            b = buf[pos]
            pos += 1
            val |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
    elif fmt == 0x02:
        val = struct.unpack_from("<H", buf, pos)[0]
        pos += 2
    elif fmt == 0x03:
        val = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
    elif fmt == 0x04:
        val = struct.unpack_from("<Q", buf, pos)[0]
        pos += 8
    elif fmt == 0x0A:
        val = struct.unpack_from("<h", buf, pos)[0]
        pos += 2
    elif fmt == 0x0B:
        val = struct.unpack_from("<i", buf, pos)[0]
        pos += 4
    elif fmt == 0x0C:
        val = struct.unpack_from("<q", buf, pos)[0]
        pos += 8
    else:
        val = struct.unpack_from("<i", buf, pos)[0]
        pos += 4

    if rel == 0x10:  # pcrel
        return (base_va + val), pos
    if rel == 0x30:  # datarel
        return (base_va + val), pos
    return val, pos


def _parse_eh_frame_functions(image: NativeElfImage) -> list[EhFunctionEntry]:
    """Extract sorted C++ function starts & sizes using .eh_frame_hdr + .eh_frame FDEs."""
    hdr = image.sections.get(".eh_frame_hdr")
    text_sec = image.sections.get(".text")
    eh_sec = image.sections.get(".eh_frame")
    if hdr is None or hdr.size < 12:
        return []

    off = hdr.offset
    ver, eh_enc, fde_enc, tbl_enc = image.buf[off : off + 4]
    if ver != 1:
        return []
    pos = off + 4
    _, pos = _read_encoded_ptr(image.buf, pos, eh_enc, hdr.addr + (pos - off))
    fde_count, pos = _read_encoded_ptr(image.buf, pos, fde_enc, hdr.addr + (pos - off))
    if fde_count <= 0 or pos + fde_count * 8 > hdr.offset + hdr.size:
        return []

    # Common ARM64 NDK encoding is DW_EH_PE_datarel | DW_EH_PE_sdata4 (0x3B)
    raw_entries: list[tuple[int, int]] = []
    if tbl_enc == 0x3B:
        for rel_pc, rel_fde in struct.iter_unpack("<ii", image.buf[pos : pos + fde_count * 8]):
            raw_entries.append((hdr.addr + rel_pc, hdr.addr + rel_fde))
    else:
        for _ in range(fde_count):
            pc, pos = _read_encoded_ptr(image.buf, pos, tbl_enc, hdr.addr)
            fde_va, pos = _read_encoded_ptr(image.buf, pos, tbl_enc, hdr.addr)
            raw_entries.append((pc, fde_va))

    # Inspect FDE pc_range (usually sdata4 right after FDE initial_location when .eh_frame uses pcrel sdata4)
    eh_end_va = eh_sec.addr + eh_sec.size if eh_sec else 0
    results: list[EhFunctionEntry] = []
    text_end = (text_sec.addr + text_sec.size) if text_sec else 0
    for idx, (pc, fde_va) in enumerate(raw_entries):
        f_size = 0
        if eh_sec and eh_sec.addr <= fde_va < eh_end_va:
            fde_off = eh_sec.offset + (fde_va - eh_sec.addr)
            if fde_off + 16 <= len(image.buf):
                # FDE header: length(u32), cie_pointer(i32), initial_location(i32), address_range(u32)
                fde_len, cie_ptr = struct.unpack_from("<Ii", image.buf, fde_off)
                if fde_len > 8 and cie_ptr > 0:
                    cand_sz = struct.unpack_from("<I", image.buf, fde_off + 12)[0]
                    if 4 <= cand_sz < 0x1000000:
                        f_size = cand_sz
        if f_size == 0 and idx + 1 < len(raw_entries):
            gap = raw_entries[idx + 1][0] - pc
            if 4 <= gap < 0x100000:
                f_size = gap
        elif f_size == 0 and text_end > pc:
            f_size = min(0x1000, text_end - pc)
        results.append(EhFunctionEntry(va=pc, size=f_size, fde_va=fde_va))
    return results


def load_native_elf(
    raw_bytes: bytes,
    log: Callable[[str], None] | None = None,
    parse_eh_frame: bool = True,
) -> NativeElfImage:
    """Parse ELF64/ELF32 binary, apply `.rela.dyn` relocations in memory, and load symbols & `.eh_frame`."""
    emit = log or (lambda _m: None)
    if len(raw_bytes) < 64 or raw_bytes[:4] != ELF_MAGIC:
        raise ValueError("File nhị phân không phải ELF hợp lệ.")

    buf = bytearray(raw_bytes)
    ei_class = buf[4]
    ei_data = buf[5]
    if ei_data != 1:
        raise ValueError("Chỉ hỗ trợ ELF little-endian.")
    is_64 = ei_class == 2

    if is_64:
        _, _, e_machine, _, _, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = (
            struct.unpack_from("<16sHHIQQQIHHHHHH", buf, 0)
        )
    else:
        _, _, e_machine, _, _, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = (
            struct.unpack_from("<16sHHIIIIIHHHHHH", buf, 0)
        )

    machine = EM_NAMES.get(e_machine, f"EM_{e_machine}")
    segments: list[ElfSegmentInfo] = []
    for i in range(e_phnum):
        p = e_phoff + i * e_phentsize
        if is_64:
            p_type, p_flags, p_off, p_va, _, p_filesz, p_memsz, _ = struct.unpack_from("<IIQQQQQQ", buf, p)
        else:
            p_type, p_off, p_va, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from("<IIIIIIII", buf, p)
        segments.append(ElfSegmentInfo(p_type, p_flags, p_off, p_va, p_filesz, p_memsz))

    raw_secs: list[tuple[int, int, int, int, int, int, int, int]] = []
    for i in range(e_shnum):
        p = e_shoff + i * e_shentsize
        if is_64:
            sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, _, _, sh_entsize = struct.unpack_from(
                "<IIQQQQIIQQ", buf, p
            )
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, _, _, sh_entsize = struct.unpack_from(
                "<IIIIIIIIII", buf, p
            )
        raw_secs.append((sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_entsize))

    shstr_off = raw_secs[e_shstrndx][4] if 0 <= e_shstrndx < len(raw_secs) else -1
    shstr_end = shstr_off + raw_secs[e_shstrndx][5] if shstr_off >= 0 else 0
    shstr_blob = bytes(buf[shstr_off:shstr_end]) if shstr_off >= 0 else b""

    sections: dict[str, ElfSectionInfo] = {}
    sec_list: list[ElfSectionInfo] = []
    for sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_entsize in raw_secs:
        name = _read_cstr(shstr_blob, sh_name) if shstr_blob else ""
        sec = ElfSectionInfo(name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_entsize)
        sec_list.append(sec)
        if name:
            sections[name] = sec

    # Load symbols (prefer .symtab if present alongside .dynsym)
    symbols: list[ElfSymbolInfo] = []
    symbols_by_idx: dict[int, ElfSymbolInfo] = {}
    symbols_by_va: dict[int, list[ElfSymbolInfo]] = {}
    bind_names = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
    type_names = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}

    dynsym_sec = next((s for s in sec_list if s.sh_type == SHT_DYNSYM), None)
    sym_sections = [s for s in sec_list if s.sh_type in (SHT_SYMTAB, SHT_DYNSYM)]
    for sym_sec in sym_sections:
        if sym_sec.link <= 0 or sym_sec.link >= len(sec_list) or sym_sec.entsize <= 0:
            continue
        str_sec = sec_list[sym_sec.link]
        str_blob = bytes(buf[str_sec.offset : str_sec.offset + str_sec.size])
        count = sym_sec.size // sym_sec.entsize
        is_dynsym = sym_sec is dynsym_sec
        for idx in range(count):
            pos = sym_sec.offset + idx * sym_sec.entsize
            if is_64:
                st_name, st_info, _, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", buf, pos)
            else:
                st_name, st_value, st_size, st_info, _, st_shndx = struct.unpack_from("<IIIBBH", buf, pos)
            name = _read_cstr(str_blob, st_name)
            bind = bind_names.get(st_info >> 4, str(st_info >> 4))
            stype = type_names.get(st_info & 0xF, str(st_info & 0xF))
            sym = ElfSymbolInfo(
                index=idx,
                name=name,
                demangled=demangle_symbol(name) if name.startswith("_Z") else name,
                value=st_value,
                size=st_size,
                binding=bind,
                sym_type=stype,
                shndx=st_shndx,
            )
            symbols.append(sym)
            if is_dynsym:
                symbols_by_idx[idx] = sym
            if st_value > 0 and name:
                symbols_by_va.setdefault(st_value, []).append(sym)

    image = NativeElfImage(
        buf=buf,
        is_64=is_64,
        machine=machine,
        segments=segments,
        sections=sections,
        symbols=symbols,
        symbols_by_idx=symbols_by_idx,
        symbols_by_va=symbols_by_va,
    )

    # Apply .rela.dyn / .rela.* relocations into in-memory ELF buffer (essential for RTTI & vtables)
    if is_64:
        for sec in sec_list:
            if sec.sh_type != SHT_RELA or sec.size <= 0:
                continue
            for r_off, r_info, r_add in struct.iter_unpack("<QQq", buf[sec.offset : sec.offset + sec.size]):
                rtype = r_info & 0xFFFFFFFF
                sym_idx = r_info >> 32
                foff = image.va_to_offset(r_off)
                if foff < 0 or foff + 8 > len(buf):
                    continue
                if rtype == R_AARCH64_RELATIVE:
                    struct.pack_into("<Q", buf, foff, r_add & 0xFFFFFFFFFFFFFFFF)
                    image.relocated_addrs.add(r_off)
                elif rtype in (R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT):
                    sym = symbols_by_idx.get(sym_idx)
                    if sym is not None:
                        image.abs64_refs[r_off] = (sym.name, r_add)
                        if sym.value > 0 and rtype == R_AARCH64_ABS64:
                            struct.pack_into("<Q", buf, foff, (sym.value + r_add) & 0xFFFFFFFFFFFFFFFF)
                            image.relocated_addrs.add(r_off)

    if parse_eh_frame:
        image.eh_functions = _parse_eh_frame_functions(image)
        emit(
            f"[ELF] {machine} ({'ELF64' if is_64 else 'ELF32'}): "
            f"{len(symbols):,} symbols, {len(image.relocated_addrs):,} relocs, "
            f"{len(image.eh_functions):,} .eh_frame functions"
        )
    return image

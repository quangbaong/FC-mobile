"""Fast ARM64 `.rodata` string classifier & ADRP+ADD function XREF analyzer."""

from __future__ import annotations

import array
from bisect import bisect_right
from dataclasses import dataclass, field
import re

from .elf_native import NativeElfImage


_CPP_MEMBER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{1,40}(?:::[A-Za-z0-9_~<>]+){1,10}$")
_DOT_CLASS_RE = re.compile(r"^(?:com|org|net|io)\.[a-z0-9_]+(?:\.[A-Za-z0-9_$]+){2,10}$")
_HX_PATH_RE = re.compile(r"^[A-Za-z0-9_/.-]+\.(?:hx|proto|cpp|h|lua)$")
_LOG_TAG_RE = re.compile(r"^\[[A-Za-z0-9_.: -]{2,40}\]")


@dataclass
class StringXrefRecord:
    va: int
    value: str
    category: str
    func_vas: list[int] = field(default_factory=list)


@dataclass
class XrefAnalysisResult:
    strings: list[StringXrefRecord] = field(default_factory=list)
    func_strings: dict[int, list[str]] = field(default_factory=dict)
    inferred_func_names: dict[int, str] = field(default_factory=dict)


def _categorize_string(s: str) -> str | None:
    if _HX_PATH_RE.match(s):
        return "source_or_proto"
    if _DOT_CLASS_RE.match(s):
        return "haxe_or_java_class"
    if _CPP_MEMBER_RE.match(s):
        return "cpp_symbol"
    if _LOG_TAG_RE.match(s):
        return "log_tag"
    if "Lua:" in s or "DGUI" in s or "dgui" in s or "EA::" in s or "fifa::" in s or "Aegis" in s:
        return "engine"
    if ("/" in s and (".cpp" in s or ".hx" in s or ".viv" in s)) or "Error" in s:
        return "diagnostic"
    return None


def _sanitize_func_hint(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_:]+", "_", text).strip("_")
    if len(cleaned) > 64:
        cleaned = cleaned[:64].rstrip("_")
    return cleaned


def scan_arm64_string_xrefs(
    image: NativeElfImage,
    max_strings: int = 60000,
) -> XrefAnalysisResult:
    """Scan `.rodata` strings and resolve ARM64 `ADRP + ADD` references mapped to `.eh_frame` functions."""
    result = XrefAnalysisResult()
    ro = image.sections.get(".rodata")
    text = image.sections.get(".text")
    if not image.is_64 or ro is None or text is None or ro.size <= 0 or text.size < 8:
        return result

    # 1. Extract interesting NUL-terminated ASCII strings from .rodata
    ro_blob = bytes(image.buf[ro.offset : ro.offset + ro.size])
    va_to_rec: dict[int, StringXrefRecord] = {}
    str_pages: set[int] = set()

    for m in re.finditer(rb"[\x20-\x7e]{5,240}(?=\x00)", ro_blob):
        # Ensure preceded by NUL or section start so we capture full string starts cleanly
        pos = m.start()
        if pos > 0 and ro_blob[pos - 1] != 0:
            continue
        s = m.group(0).decode("ascii", errors="ignore")
        cat = _categorize_string(s)
        if cat is None:
            continue
        va = ro.addr + pos
        va_to_rec[va] = StringXrefRecord(va=va, value=s, category=cat)
        str_pages.add(va & ~0xFFF)
        if len(va_to_rec) >= max_strings:
            break

    if not va_to_rec:
        return result

    func_starts = [f.va for f in image.eh_functions]
    func_ends = [f.va + f.size for f in image.eh_functions]

    def map_pc_to_func(pc: int) -> int:
        if not func_starts:
            return pc
        idx = bisect_right(func_starts, pc) - 1
        if idx >= 0 and pc < func_ends[idx]:
            return func_starts[idx]
        return pc

    # 2. Single-pass ARM64 ADRP + ADD (imm12) scanner over .text
    text_bytes = image.buf[text.offset : text.offset + text.size]
    aligned_len = (len(text_bytes) // 4) * 4
    insns = array.array("I")
    insns.frombytes(text_bytes[:aligned_len])

    ro_page_min = ro.addr & ~0xFFF
    ro_page_max = (ro.addr + ro.size) & ~0xFFF

    reg_page = [-1] * 32
    reg_idx = [0] * 32
    base_va = text.addr

    for idx, w in enumerate(insns):
        op_adrp = w & 0x9F000000
        if op_adrp == 0x90000000:
            pc = base_va + (idx << 2)
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & 0x100000:
                imm21 -= 0x200000
            page = (pc & ~0xFFF) + (imm21 << 12)
            rd = w & 31
            if ro_page_min <= page <= ro_page_max and page in str_pages:
                reg_page[rd] = page
                reg_idx[rd] = idx
            else:
                reg_page[rd] = -1
        elif (w & 0xFFC00000) == 0x91000000:
            rn = (w >> 5) & 31
            rd = w & 31
            page = reg_page[rn]
            if page >= 0 and idx - reg_idx[rn] <= 10:
                imm12 = (w >> 10) & 0xFFF
                target_va = page + imm12
                rec = va_to_rec.get(target_va)
                if rec is not None:
                    fva = map_pc_to_func(base_va + (idx << 2))
                    if not rec.func_vas or rec.func_vas[-1] != fva:
                        rec.func_vas.append(fva)
                        flist = result.func_strings.setdefault(fva, [])
                        if len(flist) < 8 and rec.value not in flist:
                            flist.append(rec.value)
            if rd != rn or page < 0:
                reg_page[rd] = -1
        elif (w & 0x7C000000) == 0x14000000 or w == 0xD65F03C0:
            # B / BL / RET boundary: reset tracking
            for r in range(32):
                reg_page[r] = -1

    # 3. Collect strings with XREFs first (plus unreferenced high-signal strings) and derive unique function hints
    with_refs = [r for r in va_to_rec.values() if r.func_vas]
    with_refs.sort(key=lambda r: (len(r.func_vas), r.va))
    for rec in with_refs:
        if len(rec.func_vas) == 1 and rec.category in ("cpp_symbol", "haxe_or_java_class", "log_tag"):
            fva = rec.func_vas[0]
            if fva not in result.inferred_func_names and fva not in image.symbols_by_va:
                hint = _sanitize_func_hint(rec.value)
                if hint:
                    result.inferred_func_names[fva] = f"ref_{hint}"

    result.strings = sorted(va_to_rec.values(), key=lambda r: (0 if r.func_vas else 1, r.category, r.va))
    return result

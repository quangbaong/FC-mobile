"""Pure-Python DEX (035-039) parser & Java<->JNI native method matcher."""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Iterable

from .elf_native import NativeElfImage


ACC_NATIVE = 0x0100
ACC_STATIC = 0x0008
ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004


@dataclass
class DexMethodRecord:
    dex_file: str
    class_desc: str
    java_class: str
    method_name: str
    return_type: str
    param_types: list[str]
    access_flags: int
    is_native: bool
    is_static: bool
    jni_c_name: str
    matched_elf_va: int = 0
    matched_elf_symbol: str = ""


@dataclass
class DexSummary:
    dex_files: list[str] = field(default_factory=list)
    total_classes: int = 0
    total_methods: int = 0
    native_methods: list[DexMethodRecord] = field(default_factory=list)
    ea_garena_packages: list[str] = field(default_factory=list)


def _read_uleb128(buf: bytes, pos: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7
    return val, pos


def _dex_type_to_java(desc: str) -> str:
    arr = ""
    while desc.startswith("["):
        arr += "[]"
        desc = desc[1:]
    prim = {
        "V": "void",
        "Z": "boolean",
        "B": "byte",
        "S": "short",
        "C": "char",
        "I": "int",
        "J": "long",
        "F": "float",
        "D": "double",
    }
    if desc in prim:
        return prim[desc] + arr
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".") + arr
    return desc + arr


def _jni_mangle(component: str) -> str:
    out: list[str] = []
    for ch in component:
        if ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        elif ch == "/":
            out.append("_")
        elif ch == "$":
            out.append("_00024")
        else:
            out.append(ch)
    return "".join(out)


def parse_dex_native_methods(dex_name: str, data: bytes) -> tuple[int, int, list[DexMethodRecord], set[str]]:
    """Parse one DEX file cleanly and return (class_count, method_count, native_methods, packages)."""
    if len(data) < 112 or not data.startswith(b"dex\n"):
        return 0, 0, [], set()

    (
        str_cnt, str_off,
        type_cnt, type_off,
        proto_cnt, proto_off,
        _fld_cnt, _fld_off,
        meth_cnt, meth_off,
        cls_cnt, cls_off,
    ) = struct.unpack_from("<12I", data, 56)

    def get_str(idx: int) -> str:
        if idx < 0 or idx >= str_cnt:
            return ""
        s_off = struct.unpack_from("<I", data, str_off + idx * 4)[0]
        _, p = _read_uleb128(data, s_off)
        end = data.find(0, p)
        if end < 0:
            end = len(data)
        return data[p:end].decode("utf-8", errors="replace")

    type_strs = [get_str(struct.unpack_from("<I", data, type_off + i * 4)[0]) for i in range(type_cnt)]

    protos: list[tuple[str, list[str]]] = []
    for i in range(proto_cnt):
        _, ret_idx, params_off = struct.unpack_from("<3I", data, proto_off + i * 12)
        ret = type_strs[ret_idx] if 0 <= ret_idx < len(type_strs) else "?"
        params: list[str] = []
        if params_off != 0 and params_off + 4 <= len(data):
            plen = struct.unpack_from("<I", data, params_off)[0]
            if plen <= 64 and params_off + 4 + plen * 2 <= len(data):
                for j in range(plen):
                    t_idx = struct.unpack_from("<H", data, params_off + 4 + j * 2)[0]
                    params.append(type_strs[t_idx] if 0 <= t_idx < len(type_strs) else "?")
        protos.append((ret, params))

    methods: list[tuple[int, int, int]] = list(
        struct.iter_unpack("<HHI", data[meth_off : meth_off + meth_cnt * 8])
    )

    packages: set[str] = set()
    natives: list[DexMethodRecord] = []

    for i in range(cls_cnt):
        class_idx, _acc, _super, _ifaces, _src, _anno, class_data_off, _svals = struct.unpack_from(
            "<8I", data, cls_off + i * 32
        )
        desc = type_strs[class_idx] if 0 <= class_idx < len(type_strs) else ""
        if desc.startswith("L") and "/" in desc:
            pkg = ".".join(desc[1:].split("/")[:3])
            if pkg.startswith(("com.ea.", "com.garena.")):
                packages.add(pkg)
        if class_data_off == 0 or class_data_off >= len(data):
            continue

        pos = class_data_off
        sf_cnt, pos = _read_uleb128(data, pos)
        if_cnt, pos = _read_uleb128(data, pos)
        dm_cnt, pos = _read_uleb128(data, pos)
        vm_cnt, pos = _read_uleb128(data, pos)

        for _ in range(sf_cnt + if_cnt):
            _, pos = _read_uleb128(data, pos)
            _, pos = _read_uleb128(data, pos)

        for list_cnt in (dm_cnt, vm_cnt):
            m_idx = 0
            for _ in range(list_cnt):
                diff, pos = _read_uleb128(data, pos)
                mflags, pos = _read_uleb128(data, pos)
                _, pos = _read_uleb128(data, pos)
                m_idx += diff
                if (mflags & ACC_NATIVE) and 0 <= m_idx < len(methods):
                    c_idx, p_idx, n_idx = methods[m_idx]
                    c_desc = type_strs[c_idx] if 0 <= c_idx < len(type_strs) else desc
                    m_name = get_str(n_idx)
                    ret_desc, param_descs = protos[p_idx] if 0 <= p_idx < len(protos) else ("?", [])
                    inner = c_desc[1:-1] if c_desc.startswith("L") and c_desc.endswith(";") else c_desc
                    jni_short = f"Java_{_jni_mangle(inner)}_{_jni_mangle(m_name)}"
                    natives.append(
                        DexMethodRecord(
                            dex_file=dex_name,
                            class_desc=c_desc,
                            java_class=inner.replace("/", "."),
                            method_name=m_name,
                            return_type=_dex_type_to_java(ret_desc),
                            param_types=[_dex_type_to_java(p) for p in param_descs],
                            access_flags=mflags,
                            is_native=True,
                            is_static=bool(mflags & ACC_STATIC),
                            jni_c_name=jni_short,
                        )
                    )
    return cls_cnt, meth_cnt, natives, packages


def analyze_dex_files(dex_blobs: Iterable[tuple[str, bytes]], elf: NativeElfImage | None = None) -> DexSummary:
    """Parse DEX files and match `native` methods to ELF `Java_*` exports when available."""
    summary = DexSummary()
    pkgs: set[str] = set()
    elf_java_syms: dict[str, tuple[str, int]] = {}
    if elf is not None:
        for sym in elf.symbols:
            if sym.value > 0 and sym.name.startswith("Java_"):
                elf_java_syms[sym.name] = (sym.name, sym.value)

    for name, blob in dex_blobs:
        summary.dex_files.append(name)
        c_cnt, m_cnt, natives, dex_pkgs = parse_dex_native_methods(name, blob)
        summary.total_classes += c_cnt
        summary.total_methods += m_cnt
        pkgs.update(dex_pkgs)
        for rec in natives:
            if rec.jni_c_name in elf_java_syms:
                rec.matched_elf_symbol, rec.matched_elf_va = elf_java_syms[rec.jni_c_name]
            else:
                overloaded_prefix = rec.jni_c_name + "__"
                for s_name, (sym_full, sym_va) in elf_java_syms.items():
                    if s_name.startswith(overloaded_prefix):
                        rec.matched_elf_symbol, rec.matched_elf_va = sym_full, sym_va
                        break
            summary.native_methods.append(rec)

    summary.ea_garena_packages = sorted(pkgs)
    return summary

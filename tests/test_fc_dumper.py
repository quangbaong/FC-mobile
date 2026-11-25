"""Unit and integration tests for FC Mobile Native C++ / Haxe / DEX Dumper."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

from fc_dumper.gui import FcDumperGuiApp
from fc_dumper.itanium_demangler import demangle_rtti_name, demangle_symbol
from fc_dumper.workflow import find_default_package, load_config
import main as fc_main


def _encode_uleb128(val: int) -> bytes:
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _encode_arm64_adrp(rd: int, pc: int, target_page: int) -> int:
    imm21 = (target_page - (pc & ~0xFFF)) >> 12
    immlo = imm21 & 3
    immhi = (imm21 >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 31)


def _encode_arm64_add_imm12(rd: int, rn: int, imm12: int) -> int:
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rd & 31)


def _build_synthetic_dex_with_native() -> bytes:
    """Build a minimal valid DEX 037 declaring `com.ea.Test.nativeInit(int): int`."""
    # Strings must be sorted in DEX conceptually (single/simple reader doesn't binary-search)
    strings = [
        "I",
        "II",
        "Lcom/ea/Test;",
        "Ljava/lang/Object;",
        "nativeInit",
    ]
    buf = bytearray(112)
    str_data_offs: list[int] = []
    # Align after header
    for s in strings:
        str_data_offs.append(len(buf))
        b = s.encode("utf-8")
        buf.extend(_encode_uleb128(len(s)))
        buf.extend(b + b"\x00")
    while len(buf) % 4 != 0:
        buf.append(0)

    str_ids_off = len(buf)
    for o in str_data_offs:
        buf.extend(struct.pack("<I", o))

    # type_ids: 0 -> "I", 1 -> "Lcom/ea/Test;", 2 -> "Ljava/lang/Object;"
    type_ids_off = len(buf)
    buf.extend(struct.pack("<3I", 0, 2, 3))

    # proto_ids: proto0: shorty="II", return="I" (type 0), params_off != 0 -> (1, [type 0])
    params_off = len(buf)
    buf.extend(struct.pack("<IH", 1, 0))
    while len(buf) % 4 != 0:
        buf.append(0)
    proto_ids_off = len(buf)
    buf.extend(struct.pack("<3I", 1, 0, params_off))

    # method_ids: method0: class_idx=1 (com.ea.Test), proto_idx=0, name_idx=4 ("nativeInit")
    method_ids_off = len(buf)
    buf.extend(struct.pack("<HHI", 1, 0, 4))

    # class_data_item: sf=0, if=0, dm=1 (method0, ACC_PUBLIC|ACC_STATIC|ACC_NATIVE=0x109, code_off=0), vm=0
    class_data_off = len(buf)
    buf.extend(_encode_uleb128(0))
    buf.extend(_encode_uleb128(0))
    buf.extend(_encode_uleb128(1))
    buf.extend(_encode_uleb128(0))
    buf.extend(_encode_uleb128(0))      # method_idx_diff = 0
    buf.extend(_encode_uleb128(0x0109)) # ACC_PUBLIC | ACC_STATIC | ACC_NATIVE
    buf.extend(_encode_uleb128(0))      # code_off = 0
    while len(buf) % 4 != 0:
        buf.append(0)

    # class_defs: 1 item (32 bytes)
    class_defs_off = len(buf)
    buf.extend(struct.pack("<8I", 1, 0x0001, 2, 0, 0xFFFFFFFF, 0, class_data_off, 0))

    # Header (112 bytes)
    file_size = len(buf)
    struct.pack_into(
        "<8sI20s20I",
        buf,
        0,
        b"dex\n037\x00",
        0,
        b"\x00" * 20,
        file_size, 112, 0x12345678, 0, 0, 0,
        len(strings), str_ids_off,
        3, type_ids_off,
        1, proto_ids_off,
        0, 0,
        1, method_ids_off,
        1, class_defs_off,
        0, 0,
    )
    return bytes(buf)


def _build_synthetic_fc_elf() -> bytes:
    """Build a synthetic ELF64 AArch64 binary with .dynsym, .rela.dyn, .eh_frame_hdr, RTTI, vtable, and XREF."""
    # Single PT_LOAD segment at vaddr 0x0 (size 0x4000)
    # Sections:
    #   0x0400: .dynstr
    #   0x0500: .dynsym (5 symbols: NULL, __class_ti_vptr, __si_class_ti_vptr, __cxa_pure_virtual, Java_com_ea_Test_nativeInit)
    #   0x0600: .rela.dyn
    #   0x0A00: .eh_frame (CIE + 3 FDEs)
    #   0x0B00: .eh_frame_hdr (ver=1, tbl=0x3B, 3 functions: 0x1000, 0x1020, 0x1040)
    #   0x1000: .text (0x100 bytes; 0x1000..0x1020 has ADRP+ADD to .rodata string; 0x1020 vfunc; 0x1040 JNI func)
    #   0x2000: .rodata (mangled RTTI names + "AFW::Crowd::MatchEngine\0")
    #   0x3000: .data.rel.ro (BaseTI @ 0x3000, DerivedTI @ 0x3020, VtableDerived @ 0x3050..0x3078)
    #   0x3800: .shstrtab
    elf = bytearray(0x4000)

    # .dynstr at 0x0400
    dynstr = bytearray(b"\x00")
    def add_dynstr(s: str) -> int:
        o = len(dynstr)
        dynstr.extend(s.encode("ascii") + b"\x00")
        return o

    d_cls = add_dynstr("_ZTVN10__cxxabiv117__class_type_infoE")
    d_si = add_dynstr("_ZTVN10__cxxabiv120__si_class_type_infoE")
    d_pure = add_dynstr("__cxa_pure_virtual")
    d_jni = add_dynstr("Java_com_ea_Test_nativeInit")
    elf[0x0400 : 0x0400 + len(dynstr)] = dynstr

    # .dynsym at 0x0500 (5 * 24 bytes: Elf64_Sym = IBBHQQ)
    struct.pack_into("<IBBHQQ", elf, 0x0500, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", elf, 0x0500 + 24, d_cls, 0x11, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", elf, 0x0500 + 48, d_si, 0x11, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", elf, 0x0500 + 72, d_pure, 0x12, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", elf, 0x0500 + 96, d_jni, 0x12, 0, 4, 0x1040, 32)  # STT_FUNC shndx=4(.text)

    # .rodata at 0x2000
    ro = bytearray()
    def add_ro(s: str) -> int:
        va = 0x2000 + len(ro)
        ro.extend(s.encode("ascii") + b"\x00")
        return va

    r_base_name = add_ro("N2hx10ObjectBaseE")
    r_drv_name = add_ro("N3com2ea4fifa14MatchState_objE")
    r_xref_str = add_ro("AFW::Crowd::MatchEngine")
    elf[0x2000 : 0x2000 + len(ro)] = ro

    # .text at 0x1000
    # func0 @ 0x1000: ADRP x0, 0x2000; ADD x0, x0, (r_xref_str & 0xFFF); RET (0xD65F03C0)
    struct.pack_into("<I", elf, 0x1000, _encode_arm64_adrp(0, 0x1000, r_xref_str & ~0xFFF))
    struct.pack_into("<I", elf, 0x1004, _encode_arm64_add_imm12(0, 0, r_xref_str & 0xFFF))
    struct.pack_into("<I", elf, 0x1008, 0xD65F03C0)
    # func1 @ 0x1020: RET
    struct.pack_into("<I", elf, 0x1020, 0xD65F03C0)
    # func2 @ 0x1040: RET
    struct.pack_into("<I", elf, 0x1040, 0xD65F03C0)

    # .eh_frame at 0x0A00 (1 CIE + 3 FDEs; simple FDE headers with pc_range=32)
    # CIE @ 0x0A00: length=16, cie_id=0
    struct.pack_into("<IiQ", elf, 0x0A00, 12, 0, 0)
    for idx, fva in enumerate((0x1000, 0x1020, 0x1040)):
        fde_va = 0x0A20 + idx * 0x20
        cie_ptr = fde_va - 0x0A00
        struct.pack_into("<IiII", elf, fde_va, 16, cie_ptr, (fva - (fde_va + 8)) & 0xFFFFFFFF, 32)

    # .eh_frame_hdr at 0x0B00: ver=1, eh_enc=0xFF(omit), fde_enc=0x03(udata4), tbl_enc=0x3B(datarel sdata4)
    eh_va = 0x0B00
    struct.pack_into("<BBBBI", elf, eh_va, 1, 0xFF, 0x03, 0x3B, 3)
    for idx, fva in enumerate((0x1000, 0x1020, 0x1040)):
        fde_va = 0x0A20 + idx * 0x20
        struct.pack_into("<ii", elf, eh_va + 8 + idx * 8, fva - eh_va, fde_va - eh_va)

    # Relocations at .rela.dyn (0x0600) pointing into .data.rel.ro (0x3000)
    # BaseTI @ 0x3000: vptr=sym[1](__class_type_info), name=r_base_name
    # DerivedTI @ 0x3020: vptr=sym[2](__si_class_type_info), name=r_drv_name, base=0x3000
    # DerivedVTable @ 0x3050: [offset_to_top=0, ti_ptr=0x3020, vfunc0=0x1000, vfunc1=sym[3](pure), vfunc2=0x1020]
    relas = [
        (0x3000, (1 << 32) | 257, 16),          # ABS64 -> BaseTI vptr
        (0x3008, 1027, r_base_name),            # RELATIVE -> BaseTI name
        (0x3020, (2 << 32) | 257, 16),          # ABS64 -> DerivedTI vptr
        (0x3028, 1027, r_drv_name),             # RELATIVE -> DerivedTI name
        (0x3030, 1027, 0x3000),                 # RELATIVE -> DerivedTI base
        (0x3058, 1027, 0x3020),                 # RELATIVE -> VTable RTTI ptr
        (0x3060, 1027, 0x1000),                 # RELATIVE -> slot 0 = 0x1000
        (0x3068, (3 << 32) | 257, 0),           # ABS64 -> slot 1 = __cxa_pure_virtual
        (0x3070, 1027, 0x1020),                 # RELATIVE -> slot 2 = 0x1020
    ]
    for i, (r_off, r_info, r_add) in enumerate(relas):
        struct.pack_into("<QQq", elf, 0x0600 + i * 24, r_off, r_info, r_add)

    # .shstrtab at 0x3800
    shstr = bytearray(b"\x00")
    def add_sh(s: str) -> int:
        o = len(shstr)
        shstr.extend(s.encode("ascii") + b"\x00")
        return o

    s_dynstr = add_sh(".dynstr")
    s_dynsym = add_sh(".dynsym")
    s_rela = add_sh(".rela.dyn")
    s_text = add_sh(".text")
    s_rodata = add_sh(".rodata")
    s_eh = add_sh(".eh_frame")
    s_ehhdr = add_sh(".eh_frame_hdr")
    s_drro = add_sh(".data.rel.ro")
    s_shstr = add_sh(".shstrtab")
    elf[0x3800 : 0x3800 + len(shstr)] = shstr

    # 1 PT_LOAD segment at 0x40
    struct.pack_into("<IIQQQQQQ", elf, 0x40, 1, 7, 0, 0, 0, len(elf), len(elf), 0x1000)

    # 10 Section Headers at 0x100 (stride 64)
    shoff = 0x100
    shdrs = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (s_dynstr, 3, 2, 0x0400, 0x0400, len(dynstr), 0, 0, 1, 0),
        (s_dynsym, 11, 2, 0x0500, 0x0500, 5 * 24, 1, 1, 8, 24),
        (s_rela, 4, 2, 0x0600, 0x0600, len(relas) * 24, 2, 0, 8, 24),
        (s_text, 1, 6, 0x1000, 0x1000, 0x100, 0, 0, 4, 0),
        (s_rodata, 1, 2, 0x2000, 0x2000, len(ro), 0, 0, 4, 0),
        (s_eh, 1, 2, 0x0A00, 0x0A00, 0x100, 0, 0, 4, 0),
        (s_ehhdr, 1, 2, 0x0B00, 0x0B00, 8 + 3 * 8, 0, 0, 4, 0),
        (s_drro, 1, 3, 0x3000, 0x3000, 0x100, 0, 0, 8, 0),
        (s_shstr, 3, 0, 0, 0x3800, len(shstr), 0, 0, 1, 0),
    ]
    for i, item in enumerate(shdrs):
        struct.pack_into("<IIQQQQIIQQ", elf, shoff + i * 64, *item)

    # ELF64 header: ET_DYN(3), EM_AARCH64(183), phnum=1, shnum=10, shstrndx=9
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        elf,
        0,
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        3, 183, 1, 0, 0x40, shoff, 0, 64, 56, 1, 64, 10, 9,
    )
    return bytes(elf)


def _zip_bytes(items: dict[str, bytes], compression: int = zipfile.ZIP_STORED) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=compression) as zf:
        for k, v in items.items():
            zf.writestr(k, v)
    return bio.getvalue()


class TestFcDumper(unittest.TestCase):
    def test_itanium_demangler(self) -> None:
        self.assertEqual(
            demangle_rtti_name("N3com2ea4fifa14MatchState_objE"),
            "com::ea::fifa::MatchState_obj",
        )
        self.assertEqual(
            demangle_rtti_name("N15MemoryFramework9Allocator15DynamicSBA_BaseILi256ELi4EEE"),
            "MemoryFramework::Allocator::DynamicSBA_Base<256, 4>",
        )
        self.assertEqual(
            demangle_symbol("_ZN8AegisSdk7Android14NdkNativeCheck17GetApkInstallPathEv"),
            "AegisSdk::Android::NdkNativeCheck::GetApkInstallPath()",
        )

    def test_config_and_default_package_detection(self) -> None:
        cfg = load_config(Path(__file__).resolve().parent.parent / "config.json")
        self.assertEqual(cfg.target_abi, "arm64-v8a")
        self.assertTrue(cfg.dump_cpp_rtti)
        self.assertTrue(cfg.dump_string_xrefs)

        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            other = tdir / "other.apk"
            fc_pkg = tdir / "FC_Mobile_VN.xapk"
            other.write_bytes(b"PK")
            fc_pkg.write_bytes(b"PK")
            self.assertEqual(find_default_package(tdir), fc_pkg.resolve())

    def test_full_fc_native_dump_cli_and_gui(self) -> None:
        elf_bytes = _build_synthetic_fc_elf()
        dex_bytes = _build_synthetic_dex_with_native()

        base_apk = _zip_bytes(
            {
                "AndroidManifest.xml": b"<manifest/>",
                "classes.dex": dex_bytes,
                "assets/Data/DynamicAssets/android/sampleIcon": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
            },
            compression=zipfile.ZIP_DEFLATED,
        )
        abi_apk = _zip_bytes({"lib/arm64-v8a/libFIFAMobileNeon.so": elf_bytes})

        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            xapk = tdir / "FC_Mobile_Test.xapk"
            with zipfile.ZipFile(xapk, "w", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr(
                    "manifest.json",
                    json.dumps({"package_name": "com.garena.game.fcmobilevn", "version_name": "33.1.02"}),
                )
                zf.writestr("config.arm64_v8a.apk", abi_apk)
                zf.writestr("com.garena.game.fcmobilevn.apk", base_apk)

            out_root = tdir / "Output"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = fc_main.main(["--dump", str(xapk), str(out_root)])
            self.assertEqual(rc, 0)

            success = [ln for ln in buf.getvalue().splitlines() if ln.startswith("DUMP_SUCCESS ")]
            self.assertEqual(len(success), 1)
            run_dir = Path(success[0].split("DUMP_SUCCESS ", 1)[1].strip())

            for req in (
                run_dir / "Input" / "libFIFAMobileNeon.so",
                run_dir / "Input" / "dex" / "classes.dex",
                run_dir / "dump_cpp.hpp",
                run_dir / "rtti_classes.json",
                run_dir / "functions.json",
                run_dir / "strings_cpp.json",
                run_dir / "jni_bridge.json",
                run_dir / "assets_index.json",
                run_dir / "ida_fc_symbols.py",
                run_dir / "ida_fc_symbols.json",
                run_dir / "ghidra_fc_symbols.py",
                run_dir / "result.json",
                run_dir / "dump.log",
            ):
                self.assertTrue(req.is_file(), f"Missing {req}")
                self.assertGreater(req.stat().st_size, 0, f"Empty {req}")

            res = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(res["packageId"], "com.garena.game.fcmobilevn")
            self.assertEqual(res["ehFrameFunctions"], 3)
            self.assertEqual(res["rttiClasses"], 2)
            self.assertEqual(res["haxeClasses"], 2)
            self.assertEqual(res["vtables"], 1)
            self.assertEqual(res["vfuncSlots"], 3)
            self.assertEqual(res["stringsWithXref"], 1)
            self.assertEqual(res["dexNativeMethods"], 1)
            self.assertEqual(res["matchedJniExports"], 1)
            self.assertEqual(res["assetsIndexed"], 1)

            hpp_txt = (run_dir / "dump_cpp.hpp").read_text(encoding="utf-8")
            self.assertIn("class com::ea::fifa::MatchState_obj : public hx::ObjectBase", hpp_txt)
            self.assertIn("AFW::Crowd::MatchEngine", hpp_txt)
            self.assertIn("Java_com_ea_Test_nativeInit", hpp_txt)

            # Verify GUI initializes cleanly in headless mode
            app = FcDumperGuiApp(initial_package=str(xapk))
            try:
                app.withdraw()
                self.assertEqual(app.package_var.get(), str(xapk.resolve()))
                self.assertEqual(app.status_var.get(), "Sẵn sàng")
            finally:
                app.destroy()


if __name__ == "__main__":
    unittest.main()

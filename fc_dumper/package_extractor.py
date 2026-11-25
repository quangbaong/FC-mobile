"""APK/XAPK extractor and asset magic-header classifier for FC Mobile & native Android packages."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import tempfile
from typing import BinaryIO
import zipfile


SUPPORTED_EXTS = {".xapk", ".apks", ".apk", ".zip"}

# Common magic prefixes inside extensionless Unity/EA DynamicAssets & install-time-assets
ASSET_MAGICS: tuple[tuple[bytes, str, str], ...] = (
    (b"PK\x03\x04", "zip_archive", ".zip"),
    (b"\x89PNG\r\n\x1a\n", "png_image", ".png"),
    (b"\xff\xd8\xff", "jpeg_image", ".jpg"),
    (b"RIFF", "webp_or_wav", ".riff"),
    (b"<?xml", "xml_doc", ".xml"),
    (b"\xef\xbb\xbf<", "xml_utf8_bom", ".xml"),
    (b"{\n", "json_doc", ".json"),
    (b"{\r\n", "json_doc", ".json"),
    (b"\x00\x01\x00\x00", "truetype_font", ".ttf"),
    (b"OTTO", "opentype_font", ".otf"),
    (b"PT0A", "ea_pt0a_archive", ".viv"),
    (b"PTCH", "ea_ptch_asset", ".ptch"),
    (b"SBle", "ea_sble_audio", ".sble"),
    (b"Clie", "ea_client_asset", ".bin"),
    (b"chunkref", "ea_chunkref", ".chunkref"),
    (b"PVR\x03", "pvr_texture", ".pvr"),
)


@dataclass
class AssetEntryInfo:
    source_apk: str
    zip_path: str
    size: int
    kind: str
    guessed_ext: str
    magic_hex: str


@dataclass
class ExtractedPackageData:
    package_name: str
    version_name: str
    version_code: str
    primary_so_entry: str
    primary_so_name: str
    primary_so_bytes: bytes
    all_so_files: dict[str, bytes] = field(default_factory=dict)
    dex_files: dict[str, bytes] = field(default_factory=dict)
    assets_index: list[AssetEntryInfo] = field(default_factory=list)
    extracted_asset_count: int = 0


def open_nested_apk(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> zipfile.ZipFile:
    """Open nested .apk safely (zero-copy for ZIP_STORED, spooled temp for compressed splits)."""
    if info.compress_type == zipfile.ZIP_STORED:
        st = zf.open(info, "r")
        try:
            return zipfile.ZipFile(st, "r")
        except Exception:
            st.close()
            raise
    spooled: BinaryIO = tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024)
    with zf.open(info, "r") as src:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            spooled.write(chunk)
    spooled.seek(0)
    return zipfile.ZipFile(spooled, "r")


def classify_asset_header(hdr: bytes) -> tuple[str, str]:
    for magic, kind, ext in ASSET_MAGICS:
        if hdr.startswith(magic):
            return kind, ext
    if hdr.startswith(b"{") or hdr.startswith(b"["):
        return "json_or_text", ".json"
    return "unknown_binary", ".bin"


def _pick_primary_so(
    so_candidates: dict[str, tuple[str, int, bytes]],
    preferred_pattern: str,
) -> tuple[str, str, bytes]:
    if not so_candidates:
        raise FileNotFoundError("Không tìm thấy thư viện native .so cho ABI mục tiêu trong package.")
    pat = preferred_pattern.lower().strip()
    if pat:
        for name, (entry, _sz, data) in so_candidates.items():
            if name.lower() == pat or pat in name.lower():
                return name, entry, data
    # Otherwise skip common runtime/anti-cheat libs and take the largest game engine library
    skip_names = {"libanogs.so", "libanort.so", "libc++_shared.so", "libcrashlytics.so"}
    ranked = sorted(
        so_candidates.items(),
        key=lambda kv: (0 if kv[0].lower() not in skip_names else 1, -kv[1][1]),
    )
    name, (entry, _sz, data) = ranked[0]
    return name, entry, data


def extract_package_contents(
    package_path: Path,
    target_abi: str = "arm64-v8a",
    target_lib_pattern: str = "libFIFAMobileNeon.so",
    extract_all_so: bool = False,
    extract_dex: bool = True,
    assets_out_dir: Path | None = None,
) -> ExtractedPackageData:
    """Extract primary native ELF, optional helper .so/DEX files, and classify assets."""
    pkg_name = ""
    ver_name = ""
    ver_code = ""
    so_candidates: dict[str, tuple[str, int, bytes]] = {}
    fallback_so: dict[str, tuple[str, int, bytes]] = {}
    dex_files: dict[str, bytes] = {}
    assets_index: list[AssetEntryInfo] = []
    extracted_assets = 0

    abi_prefix = f"lib/{target_abi}/"

    def _scan_one_zip(zf: zipfile.ZipFile, source_label: str) -> None:
        nonlocal pkg_name, ver_name, ver_code, extracted_assets
        for info in zf.infolist():
            if info.is_dir():
                continue
            fn = info.filename
            low = fn.lower()
            if not pkg_name and low == "manifest.json":
                try:
                    mj = json.loads(zf.read(info).decode("utf-8", errors="replace"))
                    if isinstance(mj, dict):
                        pkg_name = str(mj.get("package_name") or "")
                        ver_name = str(mj.get("version_name") or "")
                        ver_code = str(mj.get("version_code") or "")
                except Exception:
                    pass
            elif low.startswith(abi_prefix) and low.endswith(".so"):
                lib_name = Path(fn).name
                so_candidates[lib_name] = (f"{source_label}:{fn}", info.file_size, zf.read(info))
            elif low.startswith("lib/") and low.endswith(".so"):
                lib_name = Path(fn).name
                if lib_name not in fallback_so:
                    fallback_so[lib_name] = (f"{source_label}:{fn}", info.file_size, zf.read(info))
            elif extract_dex and "/" not in fn and low.startswith("classes") and low.endswith(".dex"):
                if fn not in dex_files:
                    dex_files[fn] = zf.read(info)
            elif low.startswith("assets/"):
                with zf.open(info, "r") as f:
                    hdr = f.read(16)
                kind, ext = classify_asset_header(hdr)
                assets_index.append(
                    AssetEntryInfo(
                        source_apk=source_label,
                        zip_path=fn,
                        size=info.file_size,
                        kind=kind,
                        guessed_ext=ext,
                        magic_hex=hdr[:8].hex(),
                    )
                )
                if assets_out_dir is not None:
                    rel = Path(*[p for p in Path(fn).parts[1:] if p not in ("..", ".")])
                    dest = (assets_out_dir / rel).resolve()
                    base_res = assets_out_dir.resolve()
                    if dest.is_relative_to(base_res):
                        if dest.suffix == "" and ext != ".bin":
                            dest = dest.with_suffix(ext)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(zf.read(info))
                        extracted_assets += 1

    with zipfile.ZipFile(package_path, "r") as zf:
        _scan_one_zip(zf, package_path.name)
        nested = sorted(
            (i for i in zf.infolist() if i.filename.lower().endswith(".apk")),
            key=lambda i: i.file_size,
        )
        for info in nested:
            with open_nested_apk(zf, info) as inner_zf:
                _scan_one_zip(inner_zf, info.filename)

    chosen_pool = so_candidates if so_candidates else fallback_so
    so_name, so_entry, so_bytes = _pick_primary_so(chosen_pool, target_lib_pattern)

    all_so: dict[str, bytes] = {so_name: so_bytes}
    if extract_all_so:
        for k, (_entry, _sz, data) in chosen_pool.items():
            all_so[k] = data

    return ExtractedPackageData(
        package_name=pkg_name,
        version_name=ver_name,
        version_code=ver_code,
        primary_so_entry=so_entry,
        primary_so_name=so_name,
        primary_so_bytes=so_bytes,
        all_so_files=all_so,
        dex_files=dex_files,
        assets_index=assets_index,
        extracted_asset_count=extracted_assets,
    )

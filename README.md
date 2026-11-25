# FC Dumper (`FC_il2cppdumper`)

Công cụ phân tích & dump tĩnh chuyên biệt cho **FC Mobile VN (`libFIFAMobileNeon.so`)** và các game Android native C++ / Haxe (`hxcpp`) không dùng Unity IL2CPP.

## Chức năng chính

- **Trích xuất package tự động**: Hỗ trợ `.xapk`, `.apks`, `.apk`, `.zip` (bao gồm split APK nén hoặc không nén). Tự tách thư viện native chính (`lib/arm64-v8a/libFIFAMobileNeon.so`), `classes*.dex`, và phân loại toàn bộ `assets/` theo magic header (`.zip`, `.png`, `.xml`, `.json`, `.ttf`, `PT0A` `.viv`, `PTCH`, `SBle`, `chunkref`).
- **Phân tích ELF64 + Relocation + `.eh_frame`**:
  - Áp dụng `.rela.dyn` (`R_AARCH64_RELATIVE`, `R_AARCH64_ABS64`, `R_AARCH64_GLOB_DAT`) trực tiếp trên bộ nhớ.
  - Trích xuất toàn bộ ranh giới hàm C++ từ `.eh_frame_hdr` / `.eh_frame` dù `.symtab` đã bị strip.
- **Khôi phục C++ RTTI, VTables & Haxe (`hxcpp`)**:
  - Tự đọc `type_info` (`__class_type_info`, `__si_class_type_info`, `__vmi_class_type_info`), demangle tên lớp Itanium C++, dựng cây kế thừa, thu hồi toàn bộ bảng vtable + địa chỉ từng virtual method (kể cả `__cxa_pure_virtual`).
- **Quét XREF ARM64 (`ADRP + ADD`) & Đối chiếu Java JNI**:
  - Gắn chuỗi C++ (`Namespace::Member`), `.proto`, `[LogTag]`, `com.ea.fifa.*` (`.hx`) vào từng hàm nguồn trong `.text`.
  - Đọc `classes*.dex` tìm toàn bộ hàm `native` của Java/Kotlin và ghép trực tiếp tới `Java_*` trong ELF.
- **Sinh artifact hoàn chỉnh**:
  - `Input/` (`.so`, `dex/`), `dump_cpp.hpp`, `rtti_classes.json`, `functions.json`, `strings_cpp.json`, `jni_bridge.json`, `assets_index.json`, `ida_fc_symbols.py` + `ida_fc_symbols.json`, `ghidra_fc_symbols.py`, `result.json`, `dump.log`.

## Sử dụng

### GUI Desktop

Chạy [launch_gui.bat](launch_gui.bat) hoặc:

```powershell
python main.py
```

### CLI (`--dump`)

```powershell
python main.py --dump "C:\path\to\FC+Mobile+VN_33.1.02_APKPure.xapk"
```

### Kiểm thử

```powershell
python -m unittest discover -s tests -v
```

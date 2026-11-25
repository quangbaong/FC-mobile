"""PlayTogether-style minimal dark desktop GUI for FC Mobile / Native C++ Dumper."""

from __future__ import annotations

import ctypes
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .workflow import DEFAULT_OUTPUT_ROOT, FcWorkflowResult, find_default_package, run_fc_dump


BG_DARK = "#111827"
BG_SURFACE = "#1E293B"
BG_BTN = "#334155"
BG_BTN_HOVER = "#475569"
BG_PRIMARY = "#2563EB"
BG_PRIMARY_HOVER = "#1D4ED8"
BORDER_COLOR = "#475569"
FG_TEXT = "#F1F5F9"
FG_MUTED = "#94A3B8"
FG_STATUS = "#93C5FD"


def _enable_dpi_awareness() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class FcDumperGuiApp(tk.Tk):
    """Minimal dark single-purpose GUI matching PlayTogether / LMHT Dumper."""

    def __init__(self, initial_package: str | None = None) -> None:
        super().__init__()
        self.title("FC Dumper")
        self.geometry("760x520")
        self.minsize(640, 420)
        self.configure(bg=BG_DARK)

        self._log_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._is_busy: bool = False
        self._last_output_dir: Path | None = None
        self._worker: threading.Thread | None = None

        self.package_var = tk.StringVar()
        self.output_var = tk.StringVar(value=str(DEFAULT_OUTPUT_ROOT))
        self.status_var = tk.StringVar(value="Sẵn sàng")

        self._configure_styles()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        if initial_package and Path(initial_package).is_file():
            detected = Path(initial_package).resolve()
            self.package_var.set(str(detected))
            self._append_log(f"Đã nạp package đầu vào: {detected}")
        else:
            auto_pkg = find_default_package()
            if auto_pkg is not None:
                self.package_var.set(str(auto_pkg))
                self._append_log(f"Tự động phát hiện package: {auto_pkg}")
            else:
                self._append_log("Chọn file .xapk / .apks / .apk / .zip rồi nhấn 'Bắt đầu dump'.")

        self.after(80, self._poll_queue)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG_DARK)
        style.configure("TLabel", background=BG_DARK, foreground=FG_TEXT, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=BG_DARK, foreground=FG_TEXT, font=("Segoe UI", 15, "bold"))
        style.configure("Muted.TLabel", background=BG_DARK, foreground=FG_MUTED, font=("Segoe UI", 9))
        style.configure("Status.TLabel", background=BG_DARK, foreground=FG_STATUS, font=("Segoe UI", 9, "bold"))
        style.configure(
            "Dark.TEntry",
            fieldbackground=BG_SURFACE,
            background=BG_SURFACE,
            foreground=FG_TEXT,
            insertcolor=FG_TEXT,
            bordercolor=BORDER_COLOR,
            lightcolor=BORDER_COLOR,
            darkcolor=BORDER_COLOR,
            padding=(8, 6),
        )
        style.configure(
            "Secondary.TButton",
            background=BG_BTN,
            foreground=FG_TEXT,
            bordercolor=BORDER_COLOR,
            focuscolor=BORDER_COLOR,
            font=("Segoe UI", 9),
            padding=(12, 6),
        )
        style.map(
            "Secondary.TButton",
            background=[("active", BG_BTN_HOVER), ("disabled", "#1F2937")],
            foreground=[("disabled", "#64748B")],
        )
        style.configure(
            "Primary.TButton",
            background=BG_PRIMARY,
            foreground="#FFFFFF",
            bordercolor=BG_PRIMARY,
            font=("Segoe UI", 9, "bold"),
            padding=(16, 6),
        )
        style.map(
            "Primary.TButton",
            background=[("active", BG_PRIMARY_HOVER), ("disabled", "#1E3A8A")],
            foreground=[("disabled", "#94A3B8")],
        )
        style.configure(
            "Dump.Horizontal.TProgressbar",
            troughcolor=BG_SURFACE,
            background=BG_PRIMARY,
            bordercolor=BORDER_COLOR,
            thickness=6,
        )

    def _build_ui(self) -> None:
        main = ttk.Frame(self, padding=16)
        main.pack(fill=tk.BOTH, expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(5, weight=1)

        hdr = ttk.Frame(main)
        hdr.grid(row=0, column=0, sticky=tk.EW, pady=(0, 12))
        ttk.Label(hdr, text="FC Dumper", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            hdr,
            text="Dump C++ RTTI / VTables / .eh_frame / ARM64 XREF / Java JNI & sinh script IDA + Ghidra",
            style="Muted.TLabel",
        ).pack(anchor=tk.W, pady=(2, 0))

        pkg_frame = ttk.Frame(main)
        pkg_frame.grid(row=1, column=0, sticky=tk.EW, pady=(0, 8))
        pkg_frame.columnconfigure(0, weight=1)
        ttk.Label(pkg_frame, text="File package (.xapk / .apks / .apk / .zip):").grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 4)
        )
        self.package_entry = ttk.Entry(pkg_frame, textvariable=self.package_var, style="Dark.TEntry")
        self.package_entry.grid(row=1, column=0, sticky=tk.EW, padx=(0, 8))
        self.browse_pkg_btn = ttk.Button(
            pkg_frame,
            text="Chọn XAPK/APK",
            style="Secondary.TButton",
            command=self._on_browse_package,
        )
        self.browse_pkg_btn.grid(row=1, column=1, sticky=tk.E)

        out_frame = ttk.Frame(main)
        out_frame.grid(row=2, column=0, sticky=tk.EW, pady=(0, 10))
        out_frame.columnconfigure(0, weight=1)
        ttk.Label(out_frame, text="Thư mục lưu kết quả:").grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 4)
        )
        self.output_entry = ttk.Entry(out_frame, textvariable=self.output_var, style="Dark.TEntry")
        self.output_entry.grid(row=1, column=0, sticky=tk.EW, padx=(0, 8))
        self.browse_out_btn = ttk.Button(
            out_frame,
            text="Chọn thư mục",
            style="Secondary.TButton",
            command=self._on_browse_output,
        )
        self.browse_out_btn.grid(row=1, column=1, sticky=tk.E)

        act_frame = ttk.Frame(main)
        act_frame.grid(row=3, column=0, sticky=tk.EW, pady=(0, 6))
        act_frame.columnconfigure(0, weight=1)
        ttk.Label(act_frame, textvariable=self.status_var, style="Status.TLabel").grid(row=0, column=0, sticky=tk.W)
        self.open_output_btn = ttk.Button(
            act_frame,
            text="Mở kết quả",
            style="Secondary.TButton",
            command=self._on_open_output,
        )
        self.open_output_btn.grid(row=0, column=1, padx=(8, 8))
        self.start_btn = ttk.Button(
            act_frame,
            text="Bắt đầu dump",
            style="Primary.TButton",
            command=self._on_start_dump,
        )
        self.start_btn.grid(row=0, column=2)

        self.progress = ttk.Progressbar(main, mode="indeterminate", style="Dump.Horizontal.TProgressbar")
        self.progress.grid(row=4, column=0, sticky=tk.EW, pady=(0, 8))

        log_frame = tk.Frame(main, bg=BORDER_COLOR, bd=1)
        log_frame.grid(row=5, column=0, sticky=tk.NSEW, pady=(0, 8))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_frame,
            bg=BG_SURFACE,
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            font=("Consolas", 9),
            relief=tk.FLAT,
            wrap=tk.WORD,
            state=tk.DISABLED,
            padx=8,
            pady=6,
        )
        self.log_text.grid(row=0, column=0, sticky=tk.NSEW)
        scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scroll.grid(row=0, column=1, sticky=tk.NS)
        self.log_text.configure(yscrollcommand=scroll.set)

        ttk.Label(
            main,
            text="Output: Input/ + dump_cpp.hpp + rtti_classes.json + functions.json + jni_bridge.json + ida_fc_symbols.py + result.json",
            style="Muted.TLabel",
        ).grid(row=6, column=0, sticky=tk.W)

    def _set_busy(self, busy: bool) -> None:
        self._is_busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.start_btn.configure(state=state)
        self.browse_pkg_btn.configure(state=state)
        self.browse_out_btn.configure(state=state)
        self.package_entry.configure(state=state)
        self.output_entry.configure(state=state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _on_browse_package(self) -> None:
        chosen = filedialog.askopenfilename(
            title="Chọn file XAPK / APKS / APK / ZIP",
            filetypes=[("Android Packages", "*.xapk *.apks *.apk *.zip"), ("All Files", "*.*")],
        )
        if chosen:
            self.package_var.set(chosen)
            self.status_var.set("Sẵn sàng")
            self._append_log(f"Đã chọn package: {chosen}")

    def _on_browse_output(self) -> None:
        chosen = filedialog.askdirectory(title="Chọn thư mục lưu kết quả")
        if chosen:
            self.output_var.set(chosen)

    def _on_open_output(self) -> None:
        target = self._last_output_dir
        if target is None or not target.exists():
            raw_out = self.output_var.get().strip()
            target = Path(raw_out) if raw_out else DEFAULT_OUTPUT_ROOT
            target.mkdir(parents=True, exist_ok=True)
        try:
            import os

            if hasattr(os, "startfile"):
                os.startfile(str(target))
        except Exception as exc:
            messagebox.showerror("Lỗi", f"Không thể mở thư mục:\n{exc}")

    def _on_start_dump(self) -> None:
        if self._is_busy:
            return
        pkg_raw = self.package_var.get().strip().strip('"')
        out_raw = self.output_var.get().strip().strip('"')
        if not pkg_raw or not Path(pkg_raw).is_file():
            messagebox.showwarning("Thiếu dữ liệu", "Vui lòng chọn file .xapk / .apks / .apk / .zip hợp lệ.")
            return
        out_root = Path(out_raw) if out_raw else DEFAULT_OUTPUT_ROOT

        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)

        self._set_busy(True)
        self.status_var.set("Đang dump...")

        def _worker() -> None:
            try:
                res = run_fc_dump(
                    package_path=Path(pkg_raw),
                    output_root=out_root,
                    log=lambda msg: self._log_queue.put(("log", msg)),
                )
                self._log_queue.put(("done", res))
            except Exception as exc:
                self._log_queue.put(("error", str(exc)))

        self._worker = threading.Thread(target=_worker, daemon=True)
        self._worker.start()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._log_queue.get_nowait()
                if kind == "log":
                    msg = str(payload)
                    self._append_log(msg)
                    if msg.startswith("["):
                        self.status_var.set(msg)
                elif kind == "done":
                    assert isinstance(payload, FcWorkflowResult)
                    self._last_output_dir = payload.output_dir
                    self._set_busy(False)
                    self.status_var.set(f"Hoàn tất: {payload.output_dir.name}")
                    self._append_log("")
                    self._append_log(f"=== THÀNH CÔNG ({payload.elapsed_seconds:.2f}s) ===")
                    self._append_log(f"Output: {payload.output_dir}")
                    self._append_log(
                        f"{payload.eh_function_count:,} functions | {payload.rtti_class_count:,} RTTI classes "
                        f"({payload.haxe_class_count:,} hxcpp) | {payload.vtable_count:,} vtables | "
                        f"{payload.matched_jni_count}/{payload.dex_native_count} JNI matched"
                    )
                elif kind == "error":
                    self._set_busy(False)
                    self.status_var.set("Dump thất bại")
                    self._append_log(f"[LỖI] {payload}")
                    messagebox.showerror("Dump thất bại", str(payload))
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(80, self._poll_queue)

    def _on_closing(self) -> None:
        if self._is_busy:
            messagebox.showinfo("Đang xử lý", "Đang chạy dump, vui lòng chờ hoàn tất trước khi đóng.")
            return
        self.destroy()


def launch_gui(initial_package: str | None = None) -> None:
    _enable_dpi_awareness()
    app = FcDumperGuiApp(initial_package=initial_package)
    app.mainloop()

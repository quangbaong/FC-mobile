"""Entry point for FC Dumper GUI and PlayTogether-style CLI `--dump`."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from fc_dumper.gui import launch_gui
from fc_dumper.workflow import run_fc_dump


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="FC Dumper — Native C++ / Haxe (hxcpp) ELF + RTTI + XREF + DEX Dumper"
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="Optional package path (.xapk/.apks/.apk/.zip), or <package> [outputDir] with --dump",
    )
    parser.add_argument(
        "--dump",
        action="store_true",
        help="Run headless dump on <package> [outputDir] and print DUMP_SUCCESS <dir>",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.dump:
        if not args.inputs:
            print("DUMP_FAILED Thiếu đường dẫn package (.xapk/.apks/.apk/.zip).", file=sys.stderr)
            return 1
        pkg_path = Path(args.inputs[0])
        out_root = Path(args.inputs[1]) if len(args.inputs) >= 2 else None
        try:
            res = run_fc_dump(pkg_path, output_root=out_root, log=print)
            print(f"DUMP_SUCCESS {res.output_dir}")
            return 0
        except Exception as exc:
            print(f"DUMP_FAILED {exc}", file=sys.stderr)
            return 1

    initial_pkg = args.inputs[0] if args.inputs else None
    launch_gui(initial_package=initial_pkg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

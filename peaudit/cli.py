"""命令行入口：批量分析目录或文件，输出 JSON 报告与一行摘要。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .report import analyze_file


def collect_paths(directory: str, extra_files: list) -> list:
    paths = []
    if directory:
        root = Path(directory)
        if not root.is_dir():
            raise SystemExit(f"目录不存在：{directory}")
        paths.extend(sorted(p for p in root.iterdir() if p.is_file()))
    paths.extend(Path(f) for f in extra_files)
    return paths


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="peaudit", description="纯标准库 PE 静态解析器")
    parser.add_argument("--dir", help="分析该目录下的所有文件")
    parser.add_argument("--out", help="JSON 报告输出路径")
    parser.add_argument("files", nargs="*", help="单独指定的 PE 文件")
    args = parser.parse_args(argv)
    paths = collect_paths(args.dir, args.files)
    entries = [analyze_file(p) for p in paths]
    report = {"files": entries}
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    parsed = sum(1 for e in entries if e["bits"] is not None)
    total_imports = sum(
        len(info["functions"])
        for e in entries
        for info in e["imports"].values()
    )
    print(f"文件数：{len(entries)}，可解析：{parsed}，导入函数总数：{total_imports}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

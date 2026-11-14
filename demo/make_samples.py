"""生成 demo/pe 下的演示样本：python demo/make_samples.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.pebuilder import build_all

if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent / "pe"
    paths = build_all(out_dir)
    for name, path in sorted(paths.items()):
        print(f"生成 {path}（{path.stat().st_size} 字节）")

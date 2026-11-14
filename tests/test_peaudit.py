"""peaudit 判定口径测试：8 条验收标准逐条对应。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from peaudit.headers import (
    PEFormatError,
    parse_dos_header,
    parse_optional_header,
)
from peaudit.report import analyze_file, parse_pe
from peaudit.rva import rva_to_offset
from tests.pebuilder import (
    SAMPLE_BUILDERS,
    build_all,
    build_pe32,
    build_pe32_plus,
)


class PEAuditTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.pe_dir = Path(cls._tmp.name) / "pe"
        cls.paths = build_all(cls.pe_dir)
        cls.entries = {
            path.name: analyze_file(path) for path in cls.paths.values()
        }

    # 口径 1：按规则造出 4 个 PE 夹具
    def test_1_fixtures_built(self):
        self.assertEqual(
            {"pe32_imports.exe", "pe64_imports.exe", "packed_upx.exe",
             "bad_lfanew.exe"},
            set(self.paths),
        )
        for name, builder in SAMPLE_BUILDERS.items():
            blob = builder()
            self.assertEqual(blob, (self.pe_dir / name).read_bytes())
            self.assertEqual(blob[0:2], b"MZ")

    # 口径 2：PE32 导入集合一个不多一个不少
    def test_2_pe32_import_set_exact(self):
        imports = self.entries["pe32_imports.exe"]["imports"]
        self.assertEqual({"kernel32.dll", "user32.dll"}, set(imports))
        self.assertEqual(
            {"CreateFileW", "ExitProcess"},
            set(imports["kernel32.dll"]["functions"]),
        )
        self.assertEqual(
            {"MessageBoxW"},
            set(imports["user32.dll"]["functions"]),
        )

    # 口径 3：PE32+ machine 为 0x8664，64 位结论依据可选头 magic 0x20B
    def test_3_pe64_machine_and_bits(self):
        entry = self.entries["pe64_imports.exe"]
        self.assertEqual(0x8664, entry["machine"])
        self.assertEqual(64, entry["bits"])
        pe = parse_pe(self.paths["pe64_imports.exe"].read_bytes())
        self.assertEqual(0x20B, pe.optional.magic)
        self.assertTrue(pe.optional.is_pe32_plus)
        self.assertEqual(64, pe.optional.bits)

    # 口径 4：RVA 0x1010 -> 文件偏移 0x410，且函数名读取正确
    def test_4_rva_mapping(self):
        pe = parse_pe(build_pe32())
        idata = next(s for s in pe.sections if s.name == ".idata")
        self.assertEqual(0x1000, idata.virtual_address)
        self.assertEqual(0x400, idata.pointer_to_raw_data)
        self.assertEqual(0x410, rva_to_offset(0x1010, pe.sections))
        self.assertEqual(0x400, rva_to_offset(0x1000, pe.sections))
        self.assertEqual(0x5FF, rva_to_offset(0x11FF, pe.sections))
        names = {
            name
            for descriptor in pe.imports
            for name in descriptor.functions
        }
        self.assertEqual(
            {"CreateFileW", "ExitProcess", "MessageBoxW"}, names)
        with self.assertRaises(PEFormatError):
            rva_to_offset(0x9000, pe.sections)

    # 口径 5：OFT 与 FT 指向不同 RVA，两者都在报告里，名字来自 Hint/Name
    def test_5_thunk_tables_distinct(self):
        imports = self.entries["pe32_imports.exe"]["imports"]
        for dll, info in imports.items():
            self.assertIn("original_first_thunk", info, dll)
            self.assertIn("first_thunk", info, dll)
            self.assertNotEqual(
                info["original_first_thunk"], info["first_thunk"], dll)
        self.assertEqual(0x1050, imports["kernel32.dll"]["original_first_thunk"])
        self.assertEqual(0x1060, imports["kernel32.dll"]["first_thunk"])
        # 函数名均来自 Hint/Name 表（非 ordinal 导入）
        for info in imports.values():
            for name in info["functions"]:
                self.assertFalse(name.startswith("ordinal_"))

    # 口径 6：UPX0/UPX1 报疑似加壳
    def test_6_packed_sections_detected(self):
        entry = self.entries["packed_upx.exe"]
        names = [s["name"] for s in entry["sections"]]
        self.assertEqual(["UPX0", "UPX1"], names)
        findings = "\n".join(entry["findings"])
        self.assertIn("疑似加壳", findings)
        self.assertIn("UPX0", findings)
        self.assertIn("UPX1", findings)

    # 口径 7：e_lfanew 错误 -> 明确原因，不抛栈，不中断批次
    def test_7_bad_lfanew_reported_not_raised(self):
        entry = self.entries["bad_lfanew.exe"]
        self.assertIsNone(entry["bits"])
        self.assertEqual({}, entry["imports"])
        findings = "\n".join(entry["findings"])
        self.assertIn("解析失败", findings)
        self.assertIn("e_lfanew", findings)
        self.assertIn("PE 签名", findings)
        # 同批次其他文件不受影响
        self.assertEqual(32, self.entries["pe32_imports.exe"]["bits"])
        self.assertEqual(64, self.entries["pe64_imports.exe"]["bits"])
        # 直接解析则应抛出 PEFormatError 而非其他异常
        with self.assertRaises(PEFormatError) as ctx:
            parse_pe(self.paths["bad_lfanew.exe"].read_bytes())
        self.assertIn("e_lfanew", str(ctx.exception))

    # 口径 8：每条报告含六个字段
    def test_8_report_fields(self):
        required = {"file", "bits", "machine", "imports", "sections",
                    "findings"}
        for name, entry in self.entries.items():
            self.assertTrue(required.issubset(entry.keys()), name)
            self.assertIsInstance(entry["imports"], dict, name)
            self.assertIsInstance(entry["sections"], list, name)
            self.assertIsInstance(entry["findings"], list, name)
        # 报告整体可 JSON 序列化
        json.dumps({"files": list(self.entries.values())},
                   ensure_ascii=False)


class HeaderUnitTests(unittest.TestCase):
    def test_dos_header_and_optional_fields(self):
        pe = parse_pe(build_pe32())
        self.assertEqual(b"MZ", pe.dos.e_magic)
        self.assertEqual(0x80, pe.dos.e_lfanew)
        self.assertEqual(0x14C, pe.coff.machine)
        self.assertEqual(2, pe.coff.number_of_sections)
        self.assertEqual(0x10B, pe.optional.magic)
        self.assertEqual(0x400000, pe.optional.image_base)
        self.assertEqual(0x1000, pe.optional.section_alignment)

    def test_pe32_plus_image_base(self):
        pe = parse_pe(build_pe32_plus())
        self.assertEqual(0x140000000, pe.optional.image_base)
        self.assertEqual(0x1000, pe.optional.section_alignment)

    def test_bad_magic_raises_clear_error(self):
        with self.assertRaises(PEFormatError) as ctx:
            parse_dos_header(b"NO" + b"\x00" * 0x40)
        self.assertIn("MZ", str(ctx.exception))

    def test_unknown_optional_magic(self):
        blob = bytearray(build_pe32())
        opt_offset = 0x80 + 4 + 20
        blob[opt_offset:opt_offset + 2] = b"\x0c\x02"
        with self.assertRaises(PEFormatError) as ctx:
            parse_optional_header(bytes(blob), opt_offset, 0xE0)
        self.assertIn("magic", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

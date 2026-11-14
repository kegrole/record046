"""把各解析器的结果组装成单文件报告，并做加壳特征判定。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .exports import parse_exports
from .headers import (
    PEFormatError,
    check_pe_signature,
    parse_coff_header,
    parse_dos_header,
    parse_optional_header,
)
from .imports import parse_imports
from .sections import parse_sections
from .tls import parse_tls

STANDARD_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc",
    ".reloc", ".tls", ".pdata", ".xdata", ".debug", ".crt", ".rodata",
    ".code", ".textbss", ".stab", ".stabstr",
}

PACKER_SECTION_NAMES = {
    "upx0", "upx1", "upx2", "upx!", ".upx0", ".upx1",
    ".aspack", ".adata", "aspack",
    ".nsp0", ".nsp1", ".nsp2",
    ".petite", ".themida", ".winlice",
    ".vmp0", ".vmp1", ".vmp2",
    ".enigma1", ".enigma2",
    "pec1", "pec2", ".pec1", ".pec2",
    ".packed", ".taz", ".tsuarch", ".sdata",
    ".neolite", ".neolit", ".mpress1", ".mpress2",
    "wwpack", ".wwpack",
}


@dataclass
class ParsedPE:
    dos: object
    coff: object
    optional: object
    sections: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    exports: object = None
    tls: object = None


def parse_pe(data: bytes) -> ParsedPE:
    """解析完整 PE；结构不符时抛出 PEFormatError 并说明原因。"""
    dos = parse_dos_header(data)
    coff_offset = check_pe_signature(data, dos.e_lfanew)
    coff, optional_offset = parse_coff_header(data, coff_offset)
    optional = parse_optional_header(data, optional_offset,
                                     coff.size_of_optional_header)
    sections_offset = optional_offset + coff.size_of_optional_header
    sections = parse_sections(data, sections_offset, coff.number_of_sections)
    return ParsedPE(
        dos=dos,
        coff=coff,
        optional=optional,
        sections=sections,
        imports=parse_imports(data, sections, optional),
        exports=parse_exports(data, sections, optional),
        tls=parse_tls(data, sections, optional),
    )


def packed_findings(sections: list) -> list:
    """加壳特征：命中已知壳节名，或全部节名都非标准。"""
    names = [s.name for s in sections]
    hits = [n for n in names if n.lower() in PACKER_SECTION_NAMES]
    if hits:
        return [
            "疑似加壳：节名 " + "、".join(hits) + " 是已知加壳器节名"
        ]
    if names and all(n.lower() not in STANDARD_SECTION_NAMES for n in names):
        return [
            "疑似加壳：所有节名均非标准节名（" + "、".join(names) + "）"
        ]
    return []


def analyze_file(path) -> dict:
    """分析单个文件，返回含六个字段的报告条目；解析失败不抛异常。"""
    entry = {
        "file": str(path),
        "bits": None,
        "machine": None,
        "imports": {},
        "sections": [],
        "findings": [],
    }
    try:
        data = Path(path).read_bytes()
        pe = parse_pe(data)
    except PEFormatError as exc:
        entry["findings"].append(f"解析失败：{exc}")
        return entry
    except OSError as exc:
        entry["findings"].append(f"解析失败：无法读取文件（{exc}）")
        return entry
    entry["bits"] = pe.optional.bits
    entry["machine"] = pe.coff.machine
    entry["sections"] = [
        {
            "name": s.name,
            "virtual_size": s.virtual_size,
            "virtual_address": s.virtual_address,
            "raw_size": s.size_of_raw_data,
        }
        for s in pe.sections
    ]
    for descriptor in pe.imports:
        entry["imports"][descriptor.dll] = {
            "functions": descriptor.functions,
            "original_first_thunk": descriptor.original_first_thunk,
            "first_thunk": descriptor.first_thunk,
        }
    entry["findings"].extend(packed_findings(pe.sections))
    if pe.exports:
        entry["findings"].append(
            f"导出目录：{pe.exports['dll'] or '(未命名)'}，"
            f"{pe.exports['number_of_functions']} 个导出函数"
        )
    if pe.tls and pe.tls["callbacks"]:
        callbacks = ", ".join(f"0x{c:x}" for c in pe.tls["callbacks"])
        entry["findings"].append(f"TLS 回调：{callbacks}")
    return entry

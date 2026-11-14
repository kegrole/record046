"""DOS 头、PE 签名、COFF 头与可选头的解析。"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


class PEFormatError(Exception):
    """PE 结构不符合预期时抛出，消息中说明具体原因。"""


PE_SIGNATURE = b"PE\x00\x00"
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B

DIRECTORY_NAMES = [
    "export", "import", "resource", "exception", "certificate", "reloc",
    "debug", "architecture", "globalptr", "tls", "load_config", "bound_import",
    "iat", "delay_import", "clr", "reserved",
]


@dataclass
class DOSHeader:
    e_magic: bytes
    e_lfanew: int


@dataclass
class COFFHeader:
    machine: int
    number_of_sections: int
    time_date_stamp: int
    characteristics: int
    size_of_optional_header: int


@dataclass
class OptionalHeader:
    magic: int
    image_base: int
    section_alignment: int
    file_alignment: int
    number_of_rva_and_sizes: int
    data_directories: list = field(default_factory=list)
    offset: int = 0
    size: int = 0

    @property
    def is_pe32_plus(self) -> bool:
        return self.magic == PE32_PLUS_MAGIC

    @property
    def bits(self) -> int:
        return 64 if self.is_pe32_plus else 32


def require(data: bytes, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise PEFormatError(
            f"{what} 超出文件范围（偏移 0x{offset:x}，需要 {size} 字节，"
            f"文件共 0x{len(data):x} 字节）"
        )


def parse_dos_header(data: bytes) -> DOSHeader:
    require(data, 0, 0x40, "DOS 头")
    e_magic = data[0:2]
    if e_magic != b"MZ":
        raise PEFormatError(f"DOS 头 e_magic 不是 MZ（实际为 {e_magic!r}）")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    return DOSHeader(e_magic=e_magic, e_lfanew=e_lfanew)


def check_pe_signature(data: bytes, e_lfanew: int) -> int:
    """校验 e_lfanew 指向的 PE 签名，返回 COFF 头偏移。"""
    require(data, e_lfanew, 4, "PE 签名（e_lfanew 指向处）")
    sig = data[e_lfanew:e_lfanew + 4]
    if sig != PE_SIGNATURE:
        raise PEFormatError(
            f"e_lfanew ({e_lfanew:#x}) 指向处不是 PE 签名（实际为 {sig!r}）"
        )
    return e_lfanew + 4


def parse_coff_header(data: bytes, offset: int) -> tuple:
    require(data, offset, 20, "COFF 头")
    (machine, number_of_sections, time_date_stamp, _ptr_sym, _num_sym,
     size_of_optional_header, characteristics) = struct.unpack_from(
        "<HHIIIHH", data, offset)
    return COFFHeader(
        machine=machine,
        number_of_sections=number_of_sections,
        time_date_stamp=time_date_stamp,
        characteristics=characteristics,
        size_of_optional_header=size_of_optional_header,
    ), offset + 20


def parse_optional_header(data: bytes, offset: int, size: int) -> OptionalHeader:
    require(data, offset, size, "可选头")
    if size < 2:
        raise PEFormatError(f"可选头大小 {size} 不足，无法读取 magic")
    (magic,) = struct.unpack_from("<H", data, offset)
    if magic == PE32_MAGIC:
        require(data, offset, 96, "PE32 可选头")
        (image_base,) = struct.unpack_from("<I", data, offset + 28)
        section_alignment, file_alignment = struct.unpack_from("<II", data, offset + 32)
        (number_of_rva_and_sizes,) = struct.unpack_from("<I", data, offset + 92)
        dir_offset = offset + 96
    elif magic == PE32_PLUS_MAGIC:
        require(data, offset, 112, "PE32+ 可选头")
        (image_base,) = struct.unpack_from("<Q", data, offset + 24)
        section_alignment, file_alignment = struct.unpack_from("<II", data, offset + 32)
        (number_of_rva_and_sizes,) = struct.unpack_from("<I", data, offset + 108)
        dir_offset = offset + 112
    else:
        raise PEFormatError(
            f"未知可选头 magic 0x{magic:04x}（既不是 0x10b 也不是 0x20b）"
        )
    directories = []
    available = (size - (dir_offset - offset)) // 8
    for i in range(min(number_of_rva_and_sizes, available, 16)):
        rva, dir_size = struct.unpack_from("<II", data, dir_offset + i * 8)
        directories.append((rva, dir_size))
    while len(directories) < 16:
        directories.append((0, 0))
    return OptionalHeader(
        magic=magic,
        image_base=image_base,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        number_of_rva_and_sizes=number_of_rva_and_sizes,
        data_directories=directories,
        offset=offset,
        size=size,
    )

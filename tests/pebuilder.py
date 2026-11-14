"""按测试口径用纯标准库构造最小 PE 样本。

布局约定（32 位与 64 位样本一致）：
- DOS 头 0x80 字节，e_lfanew = 0x80
- .idata 节：VirtualAddress = 0x1000，PointerToRawData = 0x400
- 导入描述符数组放在 RVA 0x1010，即文件偏移 0x410
- .text 节：VirtualAddress = 0x2000，PointerToRawData = 0x600
"""

from __future__ import annotations

import struct
from pathlib import Path

E_LFANEW = 0x80
IDATA_RVA = 0x1000
IDATA_RAW = 0x400
TEXT_RVA = 0x2000
TEXT_RAW = 0x600
IMPORT_DESCRIPTORS_RVA = 0x1010


def _dos_header(e_lfanew: int = E_LFANEW) -> bytes:
    header = bytearray(0x80)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, e_lfanew)
    return bytes(header)


def _coff_header(machine: int, number_of_sections: int,
                 size_of_optional_header: int) -> bytes:
    return struct.pack(
        "<HHIIIHH",
        machine,
        number_of_sections,
        0x5F2A1C00,  # TimeDateStamp
        0,
        0,
        size_of_optional_header,
        0x010F,
    )


def _optional_header_pe32(directories: dict, size_of_image: int = 0x3000) -> bytes:
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)          # Magic: PE32
    struct.pack_into("<I", opt, 4, 0x200)          # SizeOfCode
    struct.pack_into("<I", opt, 16, 0x2000)        # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, 0x400000)      # ImageBase
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)  # Section/FileAlignment
    struct.pack_into("<I", opt, 56, size_of_image)  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)         # SizeOfHeaders
    struct.pack_into("<HH", opt, 68, 3, 0)         # Subsystem = CUI
    struct.pack_into("<I", opt, 92, 16)            # NumberOfRvaAndSizes
    for index, (rva, size) in directories.items():
        struct.pack_into("<II", opt, 96 + index * 8, rva, size)
    return bytes(opt)


def _optional_header_pe32_plus(directories: dict,
                               size_of_image: int = 0x3000) -> bytes:
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)          # Magic: PE32+
    struct.pack_into("<I", opt, 4, 0x200)          # SizeOfCode
    struct.pack_into("<I", opt, 16, 0x2000)        # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)   # ImageBase
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)  # Section/FileAlignment
    struct.pack_into("<I", opt, 56, size_of_image)  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)         # SizeOfHeaders
    struct.pack_into("<HH", opt, 68, 3, 0)         # Subsystem = CUI
    struct.pack_into("<I", opt, 108, 16)           # NumberOfRvaAndSizes
    for index, (rva, size) in directories.items():
        struct.pack_into("<II", opt, 112 + index * 8, rva, size)
    return bytes(opt)


def _section_header(name: bytes, virtual_size: int, virtual_address: int,
                    raw_size: int, raw_pointer: int,
                    characteristics: int) -> bytes:
    return name.ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI",
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        0,
        0,
        0,
        0,
        characteristics,
    )


def _assemble(optional_header: bytes, section_headers: list,
              raw_parts: dict, total_size: int) -> bytes:
    headers = bytearray()
    headers += _dos_header()
    headers += b"PE\x00\x00"
    magic = struct.unpack_from("<H", optional_header, 0)[0]
    machine = 0x8664 if magic == 0x20B else 0x14C
    headers += _coff_header(machine, len(section_headers), len(optional_header))
    headers += optional_header
    for section_header in section_headers:
        headers += section_header
    image = bytearray(headers)
    if len(image) > IDATA_RAW:
        raise ValueError("头部长度超出 SizeOfHeaders")
    image += b"\x00" * (IDATA_RAW - len(image))
    for offset in sorted(raw_parts):
        blob = raw_parts[offset]
        if len(image) < offset:
            image += b"\x00" * (offset - len(image))
        image[offset:offset + len(blob)] = blob
    if len(image) < total_size:
        image += b"\x00" * (total_size - len(image))
    return bytes(image)


def build_pe32() -> bytes:
    """PE32：kernel32.dll（CreateFileW、ExitProcess）+ user32.dll（MessageBoxW）。"""
    idata = bytearray(0x200)

    def put(rva: int, blob: bytes) -> None:
        start = rva - IDATA_RVA
        idata[start:start + len(blob)] = blob

    # 导入描述符数组：RVA 0x1010（文件偏移 0x410）
    put(0x1010, struct.pack("<IIIII", 0x1050, 0, 0, 0x1090, 0x1060))
    put(0x1024, struct.pack("<IIIII", 0x1070, 0, 0, 0x10A0, 0x1080))
    # 0x1038 处保留全零终止描述符
    put(0x1050, struct.pack("<III", 0x10B0, 0x10C0, 0))   # kernel32 ILT
    put(0x1060, struct.pack("<III", 0x10B0, 0x10C0, 0))   # kernel32 IAT
    put(0x1070, struct.pack("<II", 0x10D0, 0))            # user32 ILT
    put(0x1080, struct.pack("<II", 0x10D0, 0))            # user32 IAT
    put(0x1090, b"kernel32.dll\x00")
    put(0x10A0, b"user32.dll\x00")
    put(0x10B0, struct.pack("<H", 0) + b"CreateFileW\x00")
    put(0x10C0, struct.pack("<H", 0) + b"ExitProcess\x00")
    put(0x10D0, struct.pack("<H", 0) + b"MessageBoxW\x00")

    opt = _optional_header_pe32({1: (IMPORT_DESCRIPTORS_RVA, 0x3C)})
    sections = [
        _section_header(b".idata", 0x200, IDATA_RVA, 0x200, IDATA_RAW,
                        0xC0000040),
        _section_header(b".text", 0x100, TEXT_RVA, 0x200, TEXT_RAW,
                        0x60000020),
    ]
    return _assemble(opt, sections, {IDATA_RAW: bytes(idata)}, 0x800)


def build_pe32_plus() -> bytes:
    """PE32+：kernel32.dll（CreateFileA），machine = 0x8664。"""
    idata = bytearray(0x200)

    def put(rva: int, blob: bytes) -> None:
        start = rva - IDATA_RVA
        idata[start:start + len(blob)] = blob

    put(0x1010, struct.pack("<IIIII", 0x1040, 0, 0, 0x1070, 0x1050))
    # 0x1024 处保留全零终止描述符
    put(0x1040, struct.pack("<QQ", 0x1080, 0))   # ILT
    put(0x1050, struct.pack("<QQ", 0x1080, 0))   # IAT
    put(0x1070, b"kernel32.dll\x00")
    put(0x1080, struct.pack("<H", 0) + b"CreateFileA\x00")

    opt = _optional_header_pe32_plus({1: (IMPORT_DESCRIPTORS_RVA, 0x28)})
    sections = [
        _section_header(b".idata", 0x200, IDATA_RVA, 0x200, IDATA_RAW,
                        0xC0000040),
        _section_header(b".text", 0x100, TEXT_RVA, 0x200, TEXT_RAW,
                        0x60000020),
    ]
    return _assemble(opt, sections, {IDATA_RAW: bytes(idata)}, 0x800)


def build_packed() -> bytes:
    """节名为 UPX0/UPX1 的打包壳样本，无导入目录。"""
    opt = _optional_header_pe32({}, size_of_image=0x5000)
    sections = [
        _section_header(b"UPX0", 0x3000, 0x1000, 0, 0, 0xE0000060),
        _section_header(b"UPX1", 0x1000, 0x4000, 0x200, IDATA_RAW,
                        0xE0000060),
    ]
    upx1_raw = b"UPX!" + b"\x00" * (0x200 - 4)
    return _assemble(opt, sections, {IDATA_RAW: upx1_raw}, 0x600)


def build_bad_lfanew() -> bytes:
    """e_lfanew 指向不含 PE 签名的位置。"""
    image = bytearray(0x400)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x200)  # 指向一片全零区域
    return bytes(image)


SAMPLE_BUILDERS = {
    "pe32_imports.exe": build_pe32,
    "pe64_imports.exe": build_pe32_plus,
    "packed_upx.exe": build_packed,
    "bad_lfanew.exe": build_bad_lfanew,
}


def build_all(directory) -> dict:
    """在 directory 下生成全部样本，返回 {文件名: 路径}。"""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, builder in SAMPLE_BUILDERS.items():
        path = directory / name
        path.write_bytes(builder())
        paths[name] = path
    return paths

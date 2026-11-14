"""导入目录解析：描述符、OriginalFirstThunk/FirstThunk、Hint/Name 表。"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .headers import PEFormatError, require
from .rva import rva_to_offset

IMPORT_DIRECTORY_INDEX = 1
_MAX_DESCRIPTORS = 0x1000
_MAX_THUNKS = 0x10000


@dataclass
class ImportDescriptor:
    dll: str
    functions: list = field(default_factory=list)
    original_first_thunk: int = 0
    first_thunk: int = 0


def read_cstring(data: bytes, offset: int, what: str) -> str:
    if offset < 0 or offset >= len(data):
        raise PEFormatError(f"{what} 的偏移 0x{offset:x} 超出文件范围")
    end = data.find(b"\x00", offset)
    if end == -1:
        raise PEFormatError(f"{what} 在偏移 0x{offset:x} 处缺少 NUL 结尾")
    return data[offset:end].decode("ascii", errors="replace")


def _parse_thunks(data: bytes, sections: list, is_pe32_plus: bool,
                  thunk_rva: int) -> list:
    thunk_size = 8 if is_pe32_plus else 4
    fmt = "<Q" if is_pe32_plus else "<I"
    ordinal_flag = 1 << 63 if is_pe32_plus else 1 << 31
    value_mask = (1 << 63) - 1 if is_pe32_plus else (1 << 31) - 1
    offset = rva_to_offset(thunk_rva, sections)
    names = []
    while True:
        require(data, offset, thunk_size, "thunk 表项")
        (value,) = struct.unpack_from(fmt, data, offset)
        offset += thunk_size
        if value == 0:
            break
        if value & ordinal_flag:
            names.append(f"ordinal_{value & 0xFFFF}")
        else:
            hint_name_offset = rva_to_offset(value & value_mask, sections)
            require(data, hint_name_offset, 2, "Hint/Name 表项")
            names.append(read_cstring(data, hint_name_offset + 2, "导入函数名"))
        if len(names) > _MAX_THUNKS:
            raise PEFormatError("thunk 表项数量异常，未找到终止项")
    return names


def parse_imports(data: bytes, sections: list, optional_header) -> list:
    """解析导入目录，返回 ImportDescriptor 列表；无导入目录时返回空列表。"""
    dir_rva, _dir_size = optional_header.data_directories[IMPORT_DIRECTORY_INDEX]
    if dir_rva == 0:
        return []
    offset = rva_to_offset(dir_rva, sections)
    descriptors = []
    while True:
        require(data, offset, 20, "导入描述符")
        (original_first_thunk, _timestamp, _forwarder, name_rva,
         first_thunk) = struct.unpack_from("<IIIII", data, offset)
        offset += 20
        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        if len(descriptors) >= _MAX_DESCRIPTORS:
            raise PEFormatError("导入描述符数组异常，未找到全零终止项")
        dll = read_cstring(data, rva_to_offset(name_rva, sections), "DLL 名")
        lookup_rva = original_first_thunk if original_first_thunk else first_thunk
        functions = _parse_thunks(
            data, sections, optional_header.is_pe32_plus, lookup_rva)
        descriptors.append(ImportDescriptor(
            dll=dll,
            functions=functions,
            original_first_thunk=original_first_thunk,
            first_thunk=first_thunk,
        ))
    return descriptors

"""导出目录解析。"""

from __future__ import annotations

import struct

from .headers import PEFormatError, require
from .imports import read_cstring
from .rva import rva_to_offset

EXPORT_DIRECTORY_INDEX = 0
_MAX_NAMES = 0x100000


def parse_exports(data: bytes, sections: list, optional_header):
    """解析导出目录；无导出目录时返回 None。"""
    dir_rva, _dir_size = optional_header.data_directories[EXPORT_DIRECTORY_INDEX]
    if dir_rva == 0:
        return None
    offset = rva_to_offset(dir_rva, sections)
    require(data, offset, 40, "导出目录")
    (_characteristics, _timestamp, _major, _minor, name_rva, _base,
     number_of_functions, number_of_names, _addr_functions, addr_names,
     _addr_ordinals) = struct.unpack_from("<IIHHIIIIIII", data, offset)
    dll_name = ""
    if name_rva:
        dll_name = read_cstring(data, rva_to_offset(name_rva, sections),
                                "导出 DLL 名")
    if number_of_names > _MAX_NAMES:
        raise PEFormatError(f"导出函数名数量 {number_of_names} 异常")
    names = []
    if number_of_names:
        names_offset = rva_to_offset(addr_names, sections)
        require(data, names_offset, number_of_names * 4, "导出名指针表")
        for i in range(number_of_names):
            (name_entry_rva,) = struct.unpack_from(
                "<I", data, names_offset + i * 4)
            names.append(read_cstring(
                data, rva_to_offset(name_entry_rva, sections), "导出函数名"))
    return {
        "dll": dll_name,
        "number_of_functions": number_of_functions,
        "names": names,
    }

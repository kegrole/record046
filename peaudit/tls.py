"""TLS 目录与 TLS 回调解析。"""

from __future__ import annotations

import struct

from .headers import PEFormatError, require
from .rva import rva_to_offset

TLS_DIRECTORY_INDEX = 9
_MAX_CALLBACKS = 0x1000


def parse_tls(data: bytes, sections: list, optional_header):
    """解析 TLS 目录；无 TLS 目录时返回 None。"""
    dir_rva, _dir_size = optional_header.data_directories[TLS_DIRECTORY_INDEX]
    if dir_rva == 0:
        return None
    offset = rva_to_offset(dir_rva, sections)
    if optional_header.is_pe32_plus:
        require(data, offset, 40, "TLS 目录")
        (_start, _end, _index, address_of_callbacks, _zero_fill,
         _characteristics) = struct.unpack_from("<QQQQII", data, offset)
        pointer_size, fmt = 8, "<Q"
    else:
        require(data, offset, 24, "TLS 目录")
        (_start, _end, _index, address_of_callbacks, _zero_fill,
         _characteristics) = struct.unpack_from("<IIIIII", data, offset)
        pointer_size, fmt = 4, "<I"
    callbacks = []
    if address_of_callbacks:
        callbacks_rva = address_of_callbacks - optional_header.image_base
        if callbacks_rva < 0:
            raise PEFormatError(
                f"TLS 回调表地址 0x{address_of_callbacks:x} 小于 image base")
        callback_offset = rva_to_offset(callbacks_rva, sections)
        while True:
            require(data, callback_offset, pointer_size, "TLS 回调表项")
            (value,) = struct.unpack_from(fmt, data, callback_offset)
            callback_offset += pointer_size
            if value == 0:
                break
            callbacks.append(value)
            if len(callbacks) > _MAX_CALLBACKS:
                raise PEFormatError("TLS 回调表项数量异常，未找到终止项")
    return {
        "address_of_callbacks": address_of_callbacks,
        "callbacks": callbacks,
    }

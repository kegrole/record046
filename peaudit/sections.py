"""节表解析。"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .headers import PEFormatError, require

SECTION_HEADER_SIZE = 40


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int


def parse_sections(data: bytes, offset: int, count: int) -> list:
    sections = []
    for i in range(count):
        entry_offset = offset + i * SECTION_HEADER_SIZE
        require(data, entry_offset, SECTION_HEADER_SIZE, f"第 {i} 个节表项")
        raw = data[entry_offset:entry_offset + SECTION_HEADER_SIZE]
        name = raw[0:8].split(b"\x00")[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data = (
            struct.unpack_from("<IIII", raw, 8)
        )
        (characteristics,) = struct.unpack_from("<I", raw, 36)
        sections.append(Section(
            name=name,
            virtual_size=virtual_size,
            virtual_address=virtual_address,
            size_of_raw_data=size_of_raw_data,
            pointer_to_raw_data=pointer_to_raw_data,
            characteristics=characteristics,
        ))
    return sections

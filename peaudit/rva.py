"""RVA（相对虚拟地址）到文件偏移的换算。"""

from __future__ import annotations

from .headers import PEFormatError


def rva_to_offset(rva: int, sections: list) -> int:
    """按节表把 RVA 换算成文件偏移；RVA 越界时抛出 PEFormatError。"""
    for section in sections:
        span = max(section.virtual_size, section.size_of_raw_data)
        start = section.virtual_address
        if start <= rva < start + span:
            delta = rva - start
            if delta >= section.size_of_raw_data:
                raise PEFormatError(
                    f"RVA 0x{rva:x} 落在节 {section.name} 的虚拟范围内，"
                    f"但超出其文件数据（该节原始数据大小 "
                    f"0x{section.size_of_raw_data:x}）"
                )
            return section.pointer_to_raw_data + delta
    raise PEFormatError(f"RVA 0x{rva:x} 不在任何节内，无法换算为文件偏移")

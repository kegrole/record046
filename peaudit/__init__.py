"""peaudit: 纯标准库 PE 文件静态解析器。"""

from .headers import PEFormatError
from .report import analyze_file, parse_pe

__all__ = ["PEFormatError", "analyze_file", "parse_pe"]
__version__ = "0.1.0"

# peaudit

纯 Python 标准库实现的 PE 文件静态解析器，不依赖任何第三方包。给定一个 PE 文件，把虚拟地址表（RVA）换算成文件真实偏移，再读出导入的 DLL 与函数名、节表、加壳特征等信息，输出 JSON 报告。

## 支持的 PE 结构范围

- DOS 头：校验 `e_magic` 为 MZ，读取 `e_lfanew`
- PE 签名：校验 `e_lfanew` 指向处为 PE\0\0，否则报明确原因
- COFF 头：machine、numberOfSections、timestamp、characteristics
- 可选头：按 magic 区分 PE32（0x10b）与 PE32+（0x20b），读取 image base、section alignment 与 16 个数据目录
- 节表：名称、虚拟大小、虚拟地址、原始数据大小、原始数据指针、特征位
- 导入目录：导入描述符数组、OriginalFirstThunk（ILT）与 FirstThunk（IAT）两张 thunk 表、Hint/Name 表、DLL 名与导入函数名（含 ordinal 导入）
- 导出目录：DLL 名与导出函数名表
- TLS 目录：TLS 回调地址表（32/64 位布局均支持）

## RVA 换算规则

RVA（相对虚拟地址）到文件偏移按节表逐段换算：

1. 对每个节，若 VirtualAddress <= rva < VirtualAddress + max(VirtualSize, SizeOfRawData)，则该 RVA 落在此节内；
2. 文件偏移 = PointerToRawData + (rva - VirtualAddress)；
3. 若偏移超出该节的 SizeOfRawData（落在只存在于内存的虚拟区域），或 RVA 不在任何节内，抛出 PEFormatError 并说明原因。

例：.idata 节 VirtualAddress = 0x1000、PointerToRawData = 0x400，则 RVA 0x1010 对应文件偏移 0x400 + 0x1010 - 0x1000 = 0x410。

## 加壳判定依据

满足任一条件即在 findings 中给出“疑似加壳”结论：

- 节名命中已知加壳器节名表（UPX0、UPX1、UPX2、.aspack、.adata、.nsp0、.petite、.themida、.vmp0、.enigma1、pec1 等）；
- 所有节名都不是标准节名（.text、.data、.rdata、.idata、.rsrc 等）。

## 错误处理

所有结构校验失败（e_magic 非 MZ、e_lfanew 指向处不是 PE 签名、可选头 magic 未知、RVA 越界、结构超出文件范围等）都抛出带明确中文原因的 PEFormatError；批量分析时单文件失败只在该文件的 findings 中记录“解析失败：…”，不会抛栈，也不中断整个批次。

## 用法

```bash
# 生成演示样本（tests/pebuilder.py 按固定规则构造 4 个 PE）
python demo/make_samples.py

# 批量分析并输出 JSON 报告，stdout 打印一行摘要
python -m peaudit.cli --dir demo/pe --out out/report.json

# 运行测试
python -m unittest tests.test_peaudit -v
```

报告每条记录含六个字段：file、bits、machine、imports（DLL 到函数名列表及 OFT/FT 两个 thunk 表 RVA）、sections（节名与大小）、findings。

## 目录结构

- peaudit/：解析器包（headers、sections、rva、imports、exports、tls、report、cli、__main__）
- tests/pebuilder.py：PE 样本构造器（纯标准库，按固定布局生成字节）
- tests/test_peaudit.py：unittest，覆盖全部 8 条判定口径
- demo/pe/：构造好的 4 个演示样本（PE32 双 DLL 导入、PE32+、UPX 壳、e_lfanew 错误）

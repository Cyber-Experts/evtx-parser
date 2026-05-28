---
title: "解读 EVTX 文件格式"
description: "EVTX 二进制格式的实操之旅：文件头、ELFCHNK 块、BinXML 模板、替换数组，以及为什么解析这玩意儿比看上去难。"
date: "2026-05-27"
tags:
  - evtx
  - file-format
  - binxml
  - dfir
  - reverse-engineering
author: "Florian Amette"
---

老的 EVT 格式只要有十六进制编辑器和耐心，几乎能读。EVTX 不行。Microsoft 在 Vista 中用一种为写入吞吐与机器消费而设计的格式取代了它，副作用是：每一个想读 EVTX 文件的人，最后都得重新实现 Andreas Schuster 那几百页逆向笔记里的同一批内容。`[MS-EVEN6]` 只在协议层有文档。磁盘上的结构你得自己摸或者从 `libevtx` 借。

这篇就是我开始时希望自己看到的那一版。

## 文件头，简短版

每个 EVTX 文件以 4096 字节的文件头开始。魔数是偏移 0 处的 `ElfFile\0`。之后，分诊期间你真正在意的字段：

- `FirstChunkNumber` 与 `LastChunkNumber` —— 是块索引，不是字节偏移。
- `NextRecordIdentifier` —— 下一条会被写入的 RecordID。对发现截断很有用。
- `HeaderSize` —— 几乎总是 128，4096 字节的其余部分用 0 填充。
- `MinorVersion` / `MajorVersion` —— `3.1` 是所有现代 Windows 写出来的版本。
- `FileFlags` —— bit 0 置位表示文件 dirty（未被干净关闭），bit 1 表示曾经"满了"并正在轮转。两者都对取证解读重要。
- 对文件头前 120 字节的 CRC32。忽略 CRC 的工具会高高兴兴解析损坏头；强制校验的工具则会拒绝你仍能从里面恢复出记录的文件。请知道你用的工具是哪种。

文件头之后是一连串 65,536 字节的块。永远是 64 KB，永远对齐。这是 Windows 原子写的单位，也是你雕刻时的单位。

## ELFCHNK：块头

每个块以块边界上的 `ElfChnk\0` 开头。块头有 512 字节，记录使解析成为可能的字段：

- `FirstEventRecordNumber` 与 `LastEventRecordNumber` —— 本块覆盖的 RecordID 范围。
- `FirstEventRecordIdentifier` 与 `LastEventRecordIdentifier` —— 同一信息，因为历史原因保留。
- `FirstEventRecordOffset` —— 本块内第一条记录开始的位置。
- `LastEventRecordOffset` —— 最后一条记录开始的位置。如果它超过了已填充块的末尾，说明该块只被部分写入；写入者崩溃了。
- 一张 `StringTable` 和一张 `TemplateTable`，都是以 FNV 风格哈希作键、指向块的 BinXML 载荷的哈希表。
- 两个 CRC：一个针对块头，一个针对记录区。

字符串表与模板表是让人栽跟头的部分。模板和字符串*每块只存一次*，并在块内按偏移引用。这意味着你无法在脱离上下文时有意义地解析一条记录。你需要它所属、表已经被解析的块，才能渲染出该记录的 XML。把记录从所属块中切出来雕刻，得到的就是一个没有模板可代入的替换数组。

`NumLogRecords` 隐式地等于 `LastEventRecordNumber - FirstEventRecordNumber + 1`。一些早期文档按名字提到过它；现代解析器自己算。

## EventRecord 编码

在块头之后，记录一条接一条紧挨着出现，直到块写满或剩余被清零。每条记录以魔数 `2a 2a 00 00` 开始（这让基于签名的磁盘雕刻可行 —— 另文详述），随后是：

- `Size` —— 记录总长度，含末尾的 size 重复。
- `EventRecordIdentifier` —— 单调递增的 RecordID。
- `WriteTime` —— Windows FILETIME，自 1601-01-01 UTC 起的 100ns ticks。
- BinXML 载荷。
- `Size` 再次出现在尾部，便于读取者反向遍历记录。

BinXML 载荷才是真正的工作开始的地方。

## BinXML 与模板/替换模型

BinXML 是把 XML 编码为二进制 opcode 的 token 流。要紧的 opcode：

- `0x00` end-of-stream。
- `0x01` open start tag（带属性）。
- `0x02` close start tag。
- `0x03` close empty tag。
- `0x04` end element。
- `0x05` value，后跟 `ValueType` 与值字节。
- `0x06` attribute。
- `0x0c` template instance。
- `0x0d` 普通替换。
- `0x0e` 条件替换。
- `0x0f` start of stream（带 3 字节前导）。

Windows 事件日志写入器几乎从不为一个事件直接输出 XML。它会发出一个*模板实例*（`0x0c`），引用一份模板定义（按块只存一次，用 ID 标识），并提供一个包含该模板变量值的*替换数组*。要渲染一条人类可读的 XML 记录，需要：

1. 通过模板 ID 与偏移，在块的模板表中找到该模板。
2. 沿着模板的 BinXML 行走，把它视为带编号占位符的骨架。
3. 对每个占位符，去替换数组里查对应项，与占位符声明的类型做类型校验，并把值内联进去。

替换数组里有带类型的条目：UInt32、UInt64、Boolean、GUID、FILETIME、SID、HexInt32、HexInt64、BinXML、EvtHandle、EvtXml，加上以 UTF-16LE 内联或按偏移引用的字符串，以及上述任意类型的数组。类型 0x21 是 "BinXML"，意思是替换值本身又是一段嵌套的 BinXML 流，因此解析器需要递归。这正是朴素实现常翻车的地方。

两个值得提醒的坑：

- 模板可以被同一块中*其他*记录按偏移引用。如果你写的解析器只在看到模板内联声明时才解析它，就会漏掉那些只靠 ID 引用前面模板的记录。
- "条件替换"类型（`0x0e`）的语义是：值非空则替换，否则省略父元素。跳过这个区分，会产出看上去没问题、但在真实日志原本"什么都没有"的位置出现空元素的 XML。

## 为什么比解析 EVT 更难

EVT 是一个由固定形状记录构成的平面文件。字符串以内联方式存储。一个下午就能写出解析器。

EVTX 是按页面、为写入优化、自我去重的格式。同一个字符串（"Microsoft-Windows-Security-Auditing"）在每块只存一次，并被使用它的每条记录引用。同一个 XML 骨架（"一条 4624 事件"）作为模板在每块只存一次，块内每一条 4624 记录都是基于该模板的替换数组。跨记录的状态很重要。跨块的状态不重要 —— 这是救命的设计：丢一个块就丢这些块里的记录，但文件其余部分仍可恢复。

这种去重让 EVTX 在繁忙主机上仍然足够小，也是朴素解析器出错的原因。如果你见过每条记录的 `Provider` 字段都写着 "Unknown" 的"已解析"EVTX，那就是没解析字符串表的解析器。

## 真正能用的工具

- `python-evtx`（Willi Ballenthin）—— 慢，纯 Python，但是最干净的参考实现。在你写自己的之前，先读它的源码。
- 来自 Omer Ben-Amram 的 `evtx` Rust crate 中的 `evtx_dump` —— 快、稳健，命令行 dump 的默认选择。JSONL 输出，能流到任何东西。
- `libevtx` 与 `evtxtools`（Joachim Metz）—— C 库，格式的规范参考实现。Python 绑定（`pyevtx`）在某些工作负载下比 `python-evtx` 慢，但在边界情况上更稳。
- Eric Zimmerman 的 `EvtxECmd` —— .NET 写的，因为其 maps 系统，是 IR 现场工作里同类最佳。Maps 是把 EventData 替换值展平到命名列的 YAML 文件，正是 grep 与时间线分析需要的。配上 `Timeline Explorer`。
- [本站的解析器](https://www.evtxparser.com)—— 浏览器内运行，适用于不愿把受监管数据上传给厂商、且工作主机上没有你自己工具集的场景。

如果你要从零写解析器（别这么做，但如果非要），用来验证的公共测试语料是 [SANS DFIR poster](https://github.com/forensicmatt/EVTX-ETW-Resources) 仓库与 Yamato Security `hayabusa` 的示例日志的公开 EVTX 样本。它们覆盖了你代码在第一次跑时会错的畸形块与部分记录情况。

还有一点值得说：该格式与其他 Windows 工件共享。同一种 FILETIME 编码出现在 [registry](https://www.registryparser.com)、[MFT](https://www.mftparser.com) 的 `$STANDARD_INFORMATION` 时间戳、[Prefetch](https://www.prefetchparser.com) 头里。把心算 FILETIME 练熟，许多 Windows 取证立刻安静下来。

## 延伸阅读

- Andreas Schuster 的原始 ["Introducing the Microsoft Vista Event Log File Format"](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf)（DFRWS 2007）。之后所有工作都引用的逆向论文。
- Joachim Metz 的 [libevtx 格式规范](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc)。最接近完整参考的东西。
- Willi Ballenthin 的 [python-evtx 源码](https://github.com/williballenthin/python-evtx)。读 `Evtx/Nodes.py` 看 BinXML 的节点层次。
- Omer Ben-Amram 的 [evtx Rust crate](https://github.com/omerbenamram/evtx)。多数现代工具构筑其上的那条快路径。

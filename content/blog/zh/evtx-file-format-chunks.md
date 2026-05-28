---
title: "EVTX 文件格式解读：块、模板与 BinXML 内部"
description: "一个 .evtx 文件在字节层面的布局：文件头、64 KB 块、模板表，以及引用它的 BinXML 记录流。"
date: "2026-05-17"
---

[Windows 事件日志格式 `.evtx`](/zh/blog/what-is-an-evtx-file) 随 Vista 推出，用来取代面向行的 `.evt`。它是一个二进制、只追加的、按块组织的容器，由单一进程（EventLog 服务）写入，写满即轮转。多数分析师无需知道它在字节层面如何布局。但那些从未分配空间雕刻记录、手工解析受损块，或与拒读截断文件的解析器争执的人，需要懂得很多。

本文是务实版。讲清够你调试一次坏掉的解析所需的内部细节，又不至于让你从零自己写一个解析器。

## 文件头

每个 `.evtx` 都以一个 4 KB 的文件头开始。魔数是 `ElfFile\0\0`。对调查员来说重要的字段是版本、块计数、最旧与当前块索引，以及对文件头自身的 CRC32。每次文件轮转或某个块被封闭时，文件头会就地被重写，因此它的 `Dirty` 与 `Full` 标志是有用的线索。带 `Dirty` 的文件，是在主机崩溃时或活动磁盘镜像被采集时打开着的。

文件头之后是一连串定长块。

## 块：每个 64 KB

每个块正好 65,536 字节，并有自己 512 字节的块头。块的魔数是 `ElfChnk\0`。块头记录该块中第一条与最后一条记录的日志 RecordID、文件偏移，以及两个 CRC32：一个针对块头，一个针对记录区。

块是独立的。你可以从未分配空间中雕出一个块，不需要文件其余部分就能解析。这正是 EVTX 能[从磁盘碎片中恢复](/zh/blog/carve-deleted-evtx-records)的原因，也是该格式比"跨整个文件做压缩"的方案对取证工具更友好的原因。

块内：

- **字符串表**。这个块内部 intern 的字符串，按偏移引用。
- **模板表**。块内记录使用的 XML 模板，也按偏移索引。
- **记录**。BinXML 记录流，每条引用一个模板，再加上按记录提供的替换值。

## BinXML 与模板

EVTX 记录并不以 XML 文本形式存储。它们以 **BinXML** 存储，这是 XML 文档的二进制 token 化表示。为节省空间，结构骨架（元素名、属性名、树形状）被抽出为**模板**，在块的模板表里只存一次。每条记录于是说"使用模板 ID 5，值为 [`alice`、`S-1-5-21-...`、`3`、`0xc000006a`]"。

要重建一条记录的 XML，解析器：

1. 读取该记录的 token 流。
2. 用 ID 在所属块的模板表里查到模板。
3. 把按记录提供的值代入模板里的占位符。
4. 输出最终 XML。

这就是为什么解析器（[本站的浏览器解析器](/zh/blog/how-to-open-an-evtx-file)、它所包装的 [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) crate，以及 python-evtx 都共享这个要求）必须跟踪块内上下文。模板 ID 不是跨文件全局的。两个块可以拥有完全不同的模板表；相同的模板 ID 在各自里代表不同的东西。

这也是分析师用 `xxd` 把一条记录拽出来手工解码时看到"乱码 XML"最常见的原因。没有模板表，替换值只是一袋无 schema 的类型化值。

## 封闭块 vs 脏块

当 EventLog 服务写完一个块、移到下一个时，会计算并写下该块的 CRC32，并把块头标记为 `Full`。一份干净的文件中，除最后一个外的所有块都处于这个状态。

`Dirty` 块（最后修改时间晚于文件头最近一次更新）是实时的尾部。它通常可以解析，但工具有时会拒绝读它，因为记录流可能在某个 token 中间结束。对取证而言这一点很重要：从[活动主机收集](/zh/blog/collecting-evtx-from-live-system) 的文件包，在活动通道上会有一个脏的末尾块，你需要知道你的解析器对这种块的行为。它会跳过此块、对文件报错，还是尽可能恢复出能读到的？

EvtxECmd、hayabusa 与 python-evtx 都能以不同的容忍度恢复脏块。原生的 Event Viewer 最为严格，比其他更频繁地直接拒绝文件。

## 实用启示

- 截断的 `.evtx`，在[从活动主机收集](/zh/blog/collecting-evtx-from-live-system) 时常见，多数情况下基本可恢复。每一个完整的块都是独立的。
- 从未分配空间雕出的块，可以用一个合成的文件头包装并解析。这是 libevtx 与 python-evtx 从 `pagefile.sys`（见 [pagefile 解析器](https://www.pagefilesysparser.com)）与 [RAM dump](https://www.ramparser.com) 雕刻扫描中恢复数据的方式。
- 一个块解析失败不代表整个文件失败。健壮的解析器会跳到下一个块，并把坏的那一个单独报告出来。
- 块的 CRC32 是标记篡改的依据。被修改后没有重新计算 CRC 的记录会被检出。多数攻击者不会费这个事，因为清日志（触发 [1102](/zh/blog/event-id-1102-cleared-log)）更容易。谨慎些的会用 Phant0m，根本不动文件。

## 延伸阅读

- [Andreas Schuster: Introducing the Microsoft Vista Event Log File Format](https://digital-forensics.sans.org/blog/2008/05/01/the-windows-vista-event-log-file-format)（最初的逆向工程工作）
- [libevtx 文档](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc)（野外能找到的最完整格式规范）
- [omerbenamram/evtx](https://github.com/omerbenamram/evtx)（Rust 解析器，其 WASM 构建驱动本站的浏览器解析器）

---
title: "雕刻已删除的 EVTX 记录并恢复已轮转的日志"
description: "从未分配空间、pagefile 与内存中按签名雕刻 EVTX 记录，以及当实时日志里没有你需要的内容时，能优雅处理畸形块的工具。"
date: "2026-05-27"
tags:
  - evtx
  - carving
  - dfir
  - data-recovery
  - anti-forensics
author: "Florian Amette"
---

一台繁忙的域控上的 Security 日志，是以小时而不是天为单位轮转的。默认通道大小是 20 MB，在嘈杂的主机上也就几千条记录。当你为响应三周前开始的事件而对磁盘做镜像时，你真正想看的事件早就从实时文件里滚出去，躺在未分配空间、pagefile，乃至休眠文件里。把它们雕刻回来，是任何 EVTX 主导调查的常规步骤，而大多数防御方跳过这一步，因为他们把实时文件当成事实的唯一来源。

它不是。实时文件只是最近的 20 MB。其余都在磁盘里。

## 签名：`2a 2a 00 00`

每条 EVTX 记录都以四字节的魔数 `2a 2a 00 00` 开头。即 `**` 后面跟两个空字节。这个签名足够独特，用 `bulk_extractor`、`scalpel`，甚至自定义的四字节 grep 去扫描磁盘镜像，都能返回一组有用的候选。Windows 卷上的签名密度很低，大多数命中都是真实记录。

紧随魔数的结构定义得相当清楚，你可以低成本地校验命中：

- 字节 4-7：`Size`（uint32）。应当合理（最少 32 字节，通常小于 4 KB）。
- 字节 8-15：`EventRecordIdentifier`（uint64）。应当是该时间窗口下合理的 RecordID。
- 字节 16-23：`WriteTime`，FILETIME 格式。应当落在 Vista（第一个支持 EVTX 的版本）到现在之间。
- 字节 `Size-4` 到 `Size`：同样的 `Size` 值在尾部重复出现，作为结束标记。

一个候选若头部 `Size` 与尾部 `Size` 相同、FILETIME 解析为合理日期、RecordID 在范围内，那它压倒性地很可能是真实记录。经过这四项检查，假阳性几乎为零。

挑战在于头部和尾部之间那些字节怎么办。

## 块问题

EVTX 记录会引用每个块中只存一次的模板和字符串。被孤立雕刻出的记录，其替换数组没有可应用的模板。你可以直接从替换数组中读取类型化的值，足以恢复字段级数据（"用户 X 在时间 T 从 IP Y 登录"），但实时解析器返回的渲染 XML 在没有所属块的情况下无法重建。

这正是两种雕刻结果之间的区别：

- **仅雕刻记录**：你恢复 RecordID、时间戳、EventID 和替换值。你能构建出按字段铺陈的事件视图，但拿不到给人读的渲染 XML。
- **雕刻块**：你找到一个块（魔数 `ElfChnk\0`，64 KB 对齐），并连同它的模板表与记录一起恢复。此时所有东西都有了。

`ElfChnk\0` 同样可按签名雕刻。64 KB 的对齐很有帮助，因为块落在磁盘的扇区边界上；按偏移对齐的签名扫描很快。多数雕刻工具同时支持两种模式，你应该都跑一遍。块给你可读事件；当外围块没有存活时，孤立记录补足其余。

## 字节藏在哪里

按收益从高到低值得扫描的位置：

- **承载 `%SystemRoot%\System32\winevt\Logs\` 的卷上的未分配簇**。当 EVTX 文件轮转或被清除时，旧内容会被释放为未分配。NTFS 不会清零未分配簇，因此在被复用之前，这些字节仍可恢复。在写入扰动较小的服务器上，这能持续数周。
- **实时 EVTX 文件中的 slack 空间**。EVTX 文件以 64 KB 块为单位写入。文件中的最后一个块往往只填了一部分，slack 中保留着此前写到这些字节、又被当前块缩小覆盖之前的数据。值得一扫。
- **[pagefile.sys](https://www.pagefilesysparser.com)**。事件日志服务在内存中缓存最近的记录和模板。承载这些结构的页面在内存压力下会被换出。pagefile 是那些从未被刷入磁盘的记录的金矿，因为主机崩溃或被杀掉，记录还没来得及落盘。
- **`hiberfil.sys`**。休眠时物理内存的压缩快照。用 `Volatility 3` 或 Hibr2Bin 解压，再在得到的原始内存里搜索记录签名。
- **实况响应中采集的 [RAM dump](https://www.ramparser.com)**。事件日志服务的工作集会包含最近的记录及渲染所需的模板。
- **卷影副本（VSS）**。卷的旧快照中包含实时 EVTX 文件的旧版本。`vshadow` 或 `vssadmin list shadows` 之后 `mklink /d` 挂载卷影，你就能得到一份上一代的文件副本，里面保留了卷影时刻处于实时状态的记录。

在启用且未在 VSS 层被篡改的主机上，VSS 是杠杆最高的来源。现代 Windows 服务器通常保留 7-30 天的卷影副本。如果事件发生在三周前，事件时刻的卷影可能保留着当时未被篡改的实时日志。

## 处理畸形输入的工具

在雕刻场景下，干净的 EVTX 文件很罕见。你会遇到部分块、缺少尾部的记录、引用块外偏移的模板，以及到处都是的 CRC 失败。处理这些的解析器和处理干净文件的不是同一批。

- **`EvtxECmd`**（Eric Zimmerman）。IR 现场工作的同类最佳。传 `--inc` 可以把正常解析失败的记录包含进来，并尽可能输出部分记录中能读到的内容。CSV 输出是时间线工作的首选。
- **`hayabusa`**（Yamato Security）。为在大规模 EVTX 语料中做 Sigma 风格规则狩猎而生。对部分块处理得还可以，速度快。`--exclude-status` 过滤能减少损坏记录的噪声。
- **`evtx_dump`**（Omer Ben-Amram 的 Rust crate）。对畸形结构鲁棒，输出 JSONL。适合管道给 `jq` 或 SIEM。
- **`evtxtools`**（Joachim Metz，libevtx 的一部分）。该格式的规范参考实现。比其他慢，但当记录被部分恢复时，它能精确告诉你哪个字段在哪个校验上失败了，调试雕刻输出时你正想要这个。
- **`bulk_extractor`** 配 EVTX 扫描器。雕刻这一步本身。输出带源镜像偏移的候选记录，便于后续校验。

一个实用的流水线：

1. `bulk_extractor -E evtx -o out/ image.dd` 从磁盘镜像中雕刻候选记录与块。
2. 把雕刻出的块与伪造的文件头拼接，组装成合成的 EVTX 文件。`libevtx` 的示例中包含一个兼容 `evtxexport` 的块重组器。
3. 在重组后的文件上用 `--inc` 跑 `EvtxECmd`，把所有可读内容转储到 CSV。
4. 把雕刻出的 RecordID 与实时文件的 RecordID 做差，找出不在实时日志中的记录。

第 4 步的输出就是雕刻给你的果实：被攻击者或时间从实时文件里抹去的事件。

## 当实时日志因为轮转而什么都看不到时

雕刻最常见的情形不是反取证清除，而是轮转。30 天前的事件，发生在 Security 日志 20 MB、每秒 50 条事件的主机上，文件早已整体轮转过几十次。实时日志只显示最近几小时，其间的一切都在未分配中。

这种雕刻很直白，因为没有被篡改。你扫未分配，找到块，重组。收益取决于轮转以来卷承受了多少写入扰动。系统文件大多静态、EVTX 目录是主要写入源的服务器卷，会让旧块完整保留很久。带有重应用写入的卷会更快覆盖未分配区域。

一个有用的小窍门：EVTX 目录位于 `%SystemRoot%\System32\winevt\Logs\`，在竞争写入方面是卷上最冷的位置之一。EVTX 文件轮转时释放的簇运行往往会在未分配状态保留数周。承载应用数据的卷则不能这么说。

## 恢复出的内容怎么用

雕刻出的记录与实时记录进入同一条时间线。RecordID 与 WriteTime 在雕刻过程中存活，是它们的连接键。在疑似初始接入时间出现的雕刻 `4624 Type 3`，和实时记录一样有用，仅有一个限制是你不一定能完整渲染它的 XML。

交叉参考：

- `Security.evtx` 的 [Master File Table](https://www.mftparser.com) 项，看文件何时因为清除或轮转被改写。
- EVTX 文件上的 [USN journal](https://www.usnparser.com) `DATA_OVERWRITE` 事件，给出每次轮转的高分辨率时间戳。
- 缺口期间运行过的二进制的 [Prefetch](https://www.prefetchparser.com)，因为 `Prefetch` 独立于 `Security.evtx`，能在日志清除中存活。
- [AmCache](https://www.amcacheparser.com) 与 [Shimcache](https://www.shimcacheparser.com)，作为首次执行的证据。
- 卷影副本中的 [registry](https://www.registryparser.com) 蜂巢，反映事件发生时的状态。

雕刻出的记录如果能与一条 Prefetch 项以及一个可疑二进制的 MFT 时间戳对齐，那就是一项发现。孤立的雕刻记录则是值得追下去的线索。

## 延伸阅读

- Andreas Schuster 的原始雕刻工作，见 [DFRWS 2007 论文](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf)。现代每一款工具的雕刻启发式都可追溯到此。
- Eric Zimmerman 的 [EvtxECmd](https://github.com/EricZimmerman/evtx) 文档与处理部分记录的 `--inc` 标志。
- Yamato Security 的 [hayabusa](https://github.com/Yamato-Security/hayabusa) 及其自带样例语料，便于测试雕刻流水线。
- Simson Garfinkel 的 [bulk_extractor](https://github.com/simsong/bulk_extractor) 及其 EVTX 扫描器模块。

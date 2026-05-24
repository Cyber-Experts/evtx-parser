---
title: "解读 Windows 事件日志的二进制格式"
description: "一份关于 .evtx 文件内部结构、64 KB 分块与 XML 模板机制、单条事件包含哪些信息，以及为什么这种二进制格式在 Windows 事件响应与数字取证中至关重要的简短入门。"
date: "2026-05-16"
---

Windows 事件日志 — `.evtx` — 是微软在 Windows Vista 中引入的二进制格式,用来取代更老的 `.evt`。它几乎是每一次 Windows 应急响应的脊柱:登录、服务启动、PowerShell 命令行、Sysmon 进程创建,以及一长串与提供程序相关的通道,几乎都会被序列化进来。

## 文件结构

每个 `.evtx` 文件都以一个 4 KB 的文件头开始(魔数 `ElfFile\0`、校验和、块数量),后面是一连串 64 KB 的块。每个块都有自己的块头(`ElfChnk`)、本块用到的 XML 模板表,以及一串通过模板 ID 引用这些模板的二进制记录流。解析器通过把模板的占位符与记录自身的值绑定,来重建每条事件。

## 一条记录长什么样

解码后,每条记录是一个包含两大部分的 XML 文档:

- `<System>` — 提供程序名、通道、Event ID、级别(1 严重 → 5 详细)、计算机名、安全上下文,以及写入时的 UTC 时间戳。
- `<EventData>` — 提供程序自定义的参数:登录事件中的目标账号、进程创建中的镜像路径,等等。

仅凭 Event ID 通常不足以做分诊,真正的取证信号藏在 `<EventData>` 载荷里。

## 这个工具是怎么读的

解析器是 Rust crate [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx),被编译为 WebAssembly 后加载到 Web Worker 中运行。当你拖入一个文件,Worker 会把它读入内存,遍历每一个块,并重建每条记录的 XML。整个过程不走网络 — 你可以拔掉 wifi 来验证。

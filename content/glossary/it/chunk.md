---
title: "Chunk"
description: "A 64 KB block inside an .evtx file."
date: "2026-01-01"
---

A 64 KB block inside an .evtx file. Each chunk has its own header (ElfChnk magic), a CRC-checked table of XML templates, and a stream of records that reference those templates by ID. Records cannot cross chunk boundaries.

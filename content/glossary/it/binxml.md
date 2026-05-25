---
title: "BinXML"
description: "Binary-encoded XML — the on-disk serialisation used for both templates and substitution values."
date: "2026-01-01"
---

Binary-encoded XML — the on-disk serialisation used for both templates and substitution values. Tokens (opening tag, attribute, value) are length-prefixed bytes rather than ASCII tags, which is why a hex view of an .evtx looks like nothing you can read.

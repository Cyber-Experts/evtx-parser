---
title: "Sysmon Event ID 1 を解読する:DFIR トリアージのためのプロセス作成"
description: "Sysmon のイベント 1 は Windows が生成できる最もリッチなプロセス作成レコード。中身と素早いトリアージ方法を解説。"
date: "2026-05-17"
---

Sysmon は、[Windows Event Log](/ja/blog/what-is-an-evtx-file) にベース OS では使える形で取得できないテレメトリを補強する Microsoft の無料ツールです。そのイベント ID 1 — `ProcessCreate` — は IR プレイブックで最も引用される Sysmon レコードです。ホストから 1 つの Sysmon チャネルしか抽出しないなら、これがその 1 つです。

## どこに記録され何を捕捉するか

Sysmon は `Microsoft-Windows-Sysmon/Operational` チャネル（ディスク上:`Microsoft-Windows-Sysmon%4Operational.evtx`）に書き込みます。ProcessCreate レコードは以下を含みます。

```xml
<Data Name="UtcTime">2026-05-17 14:02:11.123</Data>
<Data Name="ProcessGuid">{...}</Data>
<Data Name="ProcessId">7842</Data>
<Data Name="Image">C:\Windows\System32\powershell.exe</Data>
<Data Name="CommandLine">powershell -enc SQBFAFgA...</Data>
<Data Name="CurrentDirectory">C:\Users\alice\</Data>
<Data Name="User">CORP\alice</Data>
<Data Name="LogonId">0x3e7</Data>
<Data Name="Hashes">SHA256=...</Data>
<Data Name="ParentProcessGuid">{...}</Data>
<Data Name="ParentImage">C:\Program Files\Microsoft Office\winword.exe</Data>
<Data Name="ParentCommandLine">"winword.exe" /n /dde</Data>
```

調査を駆動するフィールド:`CommandLine`（バイナリだけでなくフル argv）、`Image` + `Hashes`（動いた正確なバイナリ、ハッシュは VT/Hybrid Analysis で利用可能）、そして `Parent*` セット（呼び出しプロセス — マクロや LOLBin 連鎖を見つけるのに重要）。

## 3 つのピボットでトリアージ

トリアージ用 Sysmon ファイルがあるとき、3 つのクエリでほとんどのケースをカバーできます。

1. **疑わしい親**:`ParentImage` が `winword.exe`、`excel.exe`、`outlook.exe`、`mshta.exe`、またはブラウザで終わり、`Image` がシェル（`cmd.exe`、`powershell.exe`、`pwsh.exe`、`wscript.exe`、`cscript.exe`、`rundll32.exe`）であるものをフィルタ。ドキュメント アプリがシェルを生むのはほぼ常に悪意。
2. **エンコード済み PowerShell**:`Image` が `powershell.exe` で終わり、`CommandLine` が `-enc`、`-encodedcommand`、または `FromBase64String` を含む。ペイロードをデコードし何をするかを確認 — そして同じホスト上の [PowerShell 4104 スクリプトブロック](/ja/blog/powershell-4104-scriptblock) レコードとクロスチェックして、実際に何が実行されたかを確認。
3. **奇妙な場所からの LOLBins**:署名済み Microsoft バイナリ（`certutil`、`regsvr32`、`mshta`、`installutil`、`bitsadmin`）が `C:\Users\`、`%TEMP%`、または `C:\ProgramData\` から起動。

## 親連鎖が重要な理由

単一の ProcessCreate はスナップショット、連鎖が物語です。`ProcessGuid` と `ParentProcessGuid` は、プロセス終了をまたいで系譜を追跡するために Sysmon が割り当てる GUID です — PID が再利用されるため、PID より信頼できます。ツリーを再構築する（各レコードの `ParentProcessGuid` は別レコードの `ProcessGuid`）と、kill-chain が明白になります:Outlook → Word → PowerShell → cmd → certutil → mshta。

## サンプル Sigma ルール — Office アプリがシェルを生む

```yaml
title: Office Application Spawning Shell or Scripting Host (Sysmon)
id: 7a4c1f2b-6e3d-4a5f-9c2a-1b3d4e5f6a7c
status: stable
description: A Microsoft Office or document-rendering process spawned cmd, powershell, wscript, cscript, mshta, rundll32 or regsvr32.
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    EventID: 1
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
      - '\acrord32.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Office add-ins running approved scripts
  - Document automation pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
  - attack.initial_access
  - attack.t1566.001
```

## サンプル KQL — 親文脈付きのエンコード済み PowerShell

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` は Sysmon 1 の `ParentCommandLine` の Defender XDR 等価物 — [4688](/ja/blog/event-id-4688-process-creation) は提供しません。

## サンプル Splunk — ユーザー書き込み可能パスからの LOLBins

```spl
sourcetype=xmlwineventlog source="*Sysmon/Operational"
  EventCode=1
  ( Image="*\\certutil.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\bitsadmin.exe" OR Image="*\\installutil.exe" OR Image="*\\msbuild.exe" )
  ( ParentImage="*\\Users\\*" OR CommandLine="*\\Users\\*"
    OR CommandLine="*%TEMP%*" OR CommandLine="*ProgramData*" )
| table _time Computer User ParentImage Image CommandLine Hashes
```

## ATT&CK マッピング

- **T1059 — Command and Scripting Interpreter** とサブ技法 `.001` PowerShell、`.003` Windows Command Shell、`.005` Visual Basic、`.007` JavaScript。
- **T1566.001 — Phishing: Spearphishing Attachment**:Office → シェル連鎖。
- **T1218 — System Binary Proxy Execution** とサブ技法 `.005` Mshta、`.010` Regsvr32、`.011` Rundll32、`.007` Msiexec。
- **T1036.003 — Masquerading: Rename System Utilities**:`OriginalFileName` ≠ `Image` のファイル名。
- **T1055 — Process Injection**:Sysmon 1 の `IntegrityLevel` と親連鎖が、`lsass.exe` や `services.exe` のようなプロセスの異常な親を見つけるのに役立つ。

## 攻撃に見える誤検知

- **ソフトウェア更新エージェント**は SYSTEM 下で日常的にシェルを生成（Chocolatey、WinGet、ベンダ MSI）。既知の自動更新ホストにタグ。
- **脆弱性スキャナ**は認証スキャン中に攻撃的プロセス ツリーを模倣。スキャナ IP にタグ。
- **Citrix / RDS** マルチセッション ホストは、攻撃者パターンと重なる高密度のプロセス作成トラフィックを生成。送信元範囲でフィルタ。
- **Defender / EDR スキャン**はオンデマンド スキャン中に異常パスから署名済み Microsoft バイナリを実行。

## カバレッジ上の注意点

Sysmon は設定が指示するもののみ捕捉します。デフォルト設定は何も記録しません。標準的リファレンスは SwiftOnSecurity の `sysmon-config` と Olaf Hartong の `sysmon-modular` です。適切な設定なしでは、イベント 1 レコードはスパースで、`CommandLine` フィールドは編集され、`Hashes` は欠ける可能性があります。ホストの Sysmon 設定をログと並べて読んでください。

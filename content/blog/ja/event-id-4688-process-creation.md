---
title: "Event ID 4688 を解説: DFIR のための Windows プロセス作成監査"
description: "4688 は、コマンドライン監査が有効なら、ベース OS のプロセス作成レコードです。中身、Sysmon 1 との違い、本領を発揮するトリアージ パターンを解説します。"
date: "2026-05-24"
---

Event ID **4688**「新しいプロセスが作成されました」は、プロセスが起動されるたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に発火します。ベース OS が [Sysmon event 1](/ja/blog/sysmon-event-id-1-process-create) の提供する telemetry に最も近づくレコードであり、Sysmon が展開されていないホストでは唯一の `CommandLine` ソースです。適切に構成された資産では、すべてのプロセス作成がこのレコードの 1 つです。よく読めば、EDR を開かずに「何が動いたか」に答えられます。

## 既定は半分盲目なので、有効化を

既定では 4688 は有効ですが `CommandLine` は**キャプチャされません**。コマンドラインなしではレコードはバイナリ パス、PID、親 PID を教えるだけで、引数については何も教えません。トリアージにはほぼ無用です。`powershell.exe` は問題ない。`powershell.exe -enc SQBFAFgA...` は問題です。

修正は Group Policy 設定:

*コンピューターの構成 / 管理用テンプレート / システム / プロセス作成の監査 / プロセス作成イベントにコマンドラインを含める*

またはレジストリ相当: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`。設定すると、すべての 4688 にフル `CommandLine` フィールドが付きます。コストはログ量。利益はバイナリ名の下にある調査面のすべて。有効化してください。

基底の監査ポリシーも必要です: `auditpol /set /subcategory:"Process Creation" /success:enable`。多くのホストはポリシーは on でコマンドラインが off です。両方を検証してください。

## レコードの中身

```xml
<Data Name="SubjectUserSid">S-1-5-21-1234-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f2a4</Data>
<Data Name="NewProcessId">0x1d34</Data>
<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
<Data Name="TokenElevationType">%%1937</Data>
<Data Name="ProcessId">0x0a1c</Data>
<Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">-</Data>
<Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
<Data Name="MandatoryLabel">S-1-16-12288</Data>
```

調査を駆動するフィールド:

- `CommandLine`。フル argv (GPO が on のとき)。
- `NewProcessName`。バイナリ パス。`CommandLine` と組み合わせて完全な実行になります。
- `ParentProcessName`。呼び出しプロセス。Office から cmd、ブラウザから powershell、services から unsigned.exe が教科書的なチェーンです。
- `SubjectUserName` と `SubjectLogonId`。誰がどのセッションで起動したか。`SubjectLogonId` はそのセッションを作成した [4624](/ja/blog/understanding-event-id-4624) に戻ります。
- `TokenElevationType`。`%%1936` Default (昇格なし)、`%%1937` Full (UAC 承諾)、`%%1938` Limited (フィルタ済み)。非管理者セッションでの `1937` は、もっとよく見るべき特権遷移です。
- `MandatoryLabel`。整合性レベル SID。`S-1-16-12288` は High (昇格)、`8192` Medium、`16384` System。

## 4688 対 Sysmon 1

重なりますが、同じではありません。

| フィールド | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Yes (GPO on で) | Yes |
| Image / NewProcessName | Yes | Yes |
| Parent image | Yes (パス) | Yes (パス + CommandLine) |
| ParentCommandLine | No | Yes |
| Image hashes (SHA/MD5/IMPHASH) | No | Yes |
| ProcessGuid (ホスト横断で安定) | No (PID は再利用) | Yes |
| ユーザー SID + 名前 | Yes | Yes |
| Logon ID | Yes | Yes |
| CurrentDirectory | No | Yes |
| Integrity level | Yes | Yes |
| インストール不要で利用可能 | Yes | Sysmon 必要 |

両方が存在する場合、[Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) の方が豊富です。`ParentCommandLine`、image ハッシュ、安定した親子チェーンのための `ProcessGuid`。4688 だけの場合、PID でチェーンを構築します。Windows は PID を再利用するため、長いタイムラインには誤マッチが含まれることがあります。常に親子リンクをタイムスタンプで相互チェックしてください。両方ない場合 (Sysmon なし、コマンドライン監査なし)、[AmCache](https://www.amcacheparser.com)、[prefetch](https://www.prefetchparser.com)、[USN journal](https://www.usnparser.com) が次善の実行証拠です。

## 本領を発揮するパターン

1. **Office からシェルへ**。`ParentProcessName` が `winword.exe`、`excel.exe`、`outlook.exe`、`powerpnt.exe`、または `mshta.exe` で終わり、`NewProcessName` が `cmd.exe`、`powershell.exe`、`pwsh.exe`、`wscript.exe`、`cscript.exe`、`rundll32.exe`、または `regsvr32.exe`。ドキュメント アプリがシェルを生むのは古典的なマクロ/フィッシング チェーン。
2. **エンコードされた PowerShell**。`NewProcessName` が `powershell.exe` で終わり、`CommandLine` が `-enc`、`-encodedcommand`、`-e ` (1 文字)、`frombase64string`、`iex `、または `invoke-expression` にマッチ。ペイロードをデコード。同じセッションの [4104 scriptblock レコード](/ja/blog/powershell-4104-scriptblock) を相互チェック。
3. **ユーザー書き込み可能パスからの LOLBin**。署名された Microsoft バイナリ (`certutil`、`regsvr32`、`mshta`、`installutil`、`bitsadmin`、`msbuild`、`csc`) が `C:\Users\`、`%TEMP%`、または `C:\ProgramData\` から起動。それらの場所での正当な利用は稀です。
4. **svchost オーファン**。`svchost.exe` の `ParentProcessName` が `services.exe` (または非常に早いブートの `wininit.exe`) 以外。本物の `svchost` は常に `services.exe` から生まれます。なりすましは目立ちます。
5. **改名バイナリ**。`NewProcessName` が中立的な何か (`update.exe`、`svc.exe`、`data.exe`) で終わり、非標準パス下にあるもの。利用可能なら Sysmon 1 の `OriginalFileName` フィールドと組み合わせ。改名された PsExec、Mimikatz、Impacket バイナリを単純な名前ベース検知をすり抜ける形で捕えます。

## Sigma: Office からシェル

```yaml
title: Office Application Spawning Shell
id: 2c8d2f4a-3c93-4b8c-bd2a-7f6b95a3b1d2
status: stable
description: An Office application launched a shell or scripting host via 4688.
references:
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
    NewProcessName|endswith:
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
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## KQL と Splunk

```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\winword.exe"
     or ParentProcessName endswith @"\excel.exe"
     or ParentProcessName endswith @"\outlook.exe"
| where NewProcessName endswith @"\cmd.exe"
     or NewProcessName endswith @"\powershell.exe"
     or NewProcessName endswith @"\pwsh.exe"
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated asc
```

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## ATT&CK マッピング

4688 の大半のカバレッジは T1059 Command and Scripting Interpreter とそのサブテクニック (.001 PowerShell、.003 Windows Command Shell、.005 Visual Basic、.007 JavaScript) に属します。LOLBin パターンは T1218 System Binary Proxy Execution (.005 Mshta、.010 Regsvr32、.011 Rundll32) にマップします。Office からシェルのチェーンは T1566.001 Phishing: Spearphishing Attachment と T1059 の組み合わせにマップします。改名バイナリ検知は T1036.003 Masquerading: Rename System Utilities にマップします。

## アラート前に読む誤検知

- ソフトウェア更新エージェントは正当にシェルを生みます: Chocolatey、WinGet、ベンダー MSI ラッパー。ユーザー アカウントではなく `SubjectUserSid` (LocalSystem) と安定した `ParentProcessName` パターンでホワイトリスト化。
- 脆弱性スキャナーと EDR 製品は、攻撃者が偵察しているかのように見えるプロセス ツリーを生成します: `net.exe`、`whoami.exe`、`systeminfo.exe`。スキャナー IP とホストにタグ。
- Citrix と RDS のマルチセッション ボックスは、ドメイン横断アクセスのために正当な `runas /netonly` チェーンを見ます。ユーザーを調べ、パターンではなく。
- ログオン スクリプト (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) は各ログオンで発火し、繰り返すチェーンとして現れます。アラート前にベースライン化。

## 4688 が教えないこと

ファイル ハッシュなし。`ParentCommandLine` なし。`ImageLoaded` なし (DLL 注入はプロセス作成ではない)。ネットワーク動作なし。それらには [Sysmon event 1](/ja/blog/sysmon-event-id-1-process-create) (より豊富な 4688)、Sysmon 7 (image load)、Sysmon 3/22 (network/DNS)、EDR の振る舞い telemetry が必要です。4688 はプロセス可視性の床です。すべての Windows ホストが持つべき最低限。重要なホスト上の適切な EDR + Sysmon の代替ではありません。

## タイムラインでの 4688 の位置

Sysmon なしホスト上の典型的なエクスプロイト後チェーンの場合:

1. [4624](/ja/blog/understanding-event-id-4624)。初期ログオン、外部 IP からの LogonType 3。
2. もう 1 つの 4624。同じ `SubjectLogonId` 下の LogonType 9 (`runas /netonly`)。資格情報ピボット。
3. **4688**。そのセッション下の `powershell.exe -enc ...`。
4. [4104](/ja/blog/powershell-4104-scriptblock)。デコードされたスクリプト本体、2 段目のペイロードをフェッチ。
5. **4688**。`%TEMP%` から動く 2 段目バイナリ。
6. [7045](/ja/blog/service-creation-event-id-7045)。永続化のためにインストールされたサービス。

6 つのレコードが物語全体を語ります。(3) と (5) の PID は、4688 の `ProcessId` と `NewProcessId` でつながりますが、Windows は PID を再利用するのでタイムスタンプで検証してください。Sysmon が存在すれば、`ProcessGuid` チェーンがその脆いマッチを置き換えます。

## 参考資料

- [4688 の Microsoft ドキュメント](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

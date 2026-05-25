---
title: "Event ID 4688 を解読する:DFIR のための Windows プロセス作成監査"
description: "4688 はベース OS のプロセス作成レコード — コマンドライン監査がオンなら。Sysmon 1 との違い、そして元を取れるトリアージ パターンを解説。"
date: "2026-05-24"
---

Event ID **4688** — 「新しいプロセスが作成されました」 — は、プロセスが起動するたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に記録されます。これはベース OS が提供する最も [Sysmon イベント 1](/ja/blog/sysmon-event-id-1-process-create) に近いテレメトリで — Sysmon がデプロイされていないホストでは、唯一の `CommandLine` ソースになります。正しく構成された環境では、すべてのプロセス作成がこのレコードの 1 つです。これを上手く読めば、EDR を開かずに「何が動いたか」に答えられます。

## 有効化する（デフォルトは半盲のため）

デフォルトでは 4688 は有効ですが、`CommandLine` は**取得されません**。`CommandLine` がなければ、レコードはバイナリ パス、PID、親 PID を伝えるだけで、引数については何も語りません。トリアージにはほぼ使い物になりません:`powershell.exe` は問題なし、`powershell.exe -enc SQBFAFgA…` は問題あり。

修正はグループ ポリシーの設定です。

*コンピュータの構成 → 管理用テンプレート → システム → プロセス作成の監査 → プロセス作成イベントにコマンド ライン情報を含める*

またはレジストリ等価:`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`。設定後、すべての 4688 にフル `CommandLine` フィールドが付きます。コストはログ量、恩恵はバイナリ名の下にある調査面全体です。オンにしましょう。

基盤の監査ポリシーもオンが必要です:`auditpol /set /subcategory:"Process Creation" /success:enable`。多くのホストはポリシーはオンだがコマンドラインはオフ — 両方を検証してください。

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

すべての調査を駆動するフィールド。

- **`CommandLine`** — フル argv（GPO がオンの場合）。
- **`NewProcessName`** — バイナリ パス。`CommandLine` と組み合わせて完全な実行。
- **`ParentProcessName`** — 呼び出しプロセス。Office → cmd、ブラウザ → powershell、services → unsigned.exe は教科書的な連鎖。
- **`SubjectUserName` / `SubjectLogonId`** — 誰がどのセッションで起動したか。`SubjectLogonId` はセッションを作成した [4624](/ja/blog/understanding-event-id-4624) と同セッションの他レコードへ遡るピボット。
- **`TokenElevationType`** — `%%1936` Default（昇格なし）、`%%1937` Full（UAC 同意あり）、`%%1938` Limited（フィルタ済み）。非管理者セッションでの `1937` は特権遷移で要注意。
- **`MandatoryLabel`** — 整合性レベル SID。`S-1-16-12288` が High（昇格）、`8192` が Medium、`16384` が System。

## 4688 vs Sysmon 1

重複しますが、同じではありません。

| フィールド | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | あり（GPO オン時） | あり |
| Image / NewProcessName | あり | あり |
| 親イメージ | あり（パス） | あり（パス + CommandLine） |
| ParentCommandLine | なし | あり |
| ImageHash（SHA/MD5/IMPHASH） | なし | あり |
| ProcessGuid（クロスホストで安定） | なし（PID のみ、再利用される） | あり |
| User SID + 名前 | あり | あり |
| Logon ID | あり | あり |
| CurrentDirectory | なし | あり |
| 整合性レベル | あり | あり |
| インストール不要で利用可 | あり | Sysmon が必要 |

両方が存在するとき、[Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) のほうがリッチです — `ParentCommandLine`、イメージ ハッシュ、安定した親子連鎖のための ProcessGuid。4688 のみのとき、PID（Windows が再利用する）で連鎖を組み立てるため、長いタイムラインでは誤マッチが入り得ます。タイムスタンプで親子リンクを必ずクロスチェックしてください。

## トリアージ パターン

4688 レコードのコーパスで、元を取れるパターン。

1. **Office → シェル**:`ParentProcessName` が `winword.exe`、`excel.exe`、`outlook.exe`、`powerpnt.exe`、または `mshta.exe` で終わり、`NewProcessName` が `cmd.exe`、`powershell.exe`、`pwsh.exe`、`wscript.exe`、`cscript.exe`、`rundll32.exe`、または `regsvr32.exe`。ドキュメント アプリがシェルを生むのは古典的マクロ / フィッシング連鎖。
2. **エンコード済み PowerShell**:`NewProcessName` が `powershell.exe` で終わり、`CommandLine` が `-enc`、`-encodedcommand`、`-e `（1 文字）、`frombase64string`、`iex `、または `invoke-expression` にマッチ。ペイロードをデコードし、同じセッションの [4104 スクリプトブロック レコード](/ja/blog/powershell-4104-scriptblock) とクロスチェック。
3. **ユーザー書き込み可能パスからの LOLBins**:署名済み Microsoft バイナリ（`certutil`、`regsvr32`、`mshta`、`installutil`、`bitsadmin`、`msbuild`、`csc`）が `C:\Users\`、`%TEMP%`、または `C:\ProgramData\` から起動。これらの場所での正当な使用は稀。
4. **Service host のオーファン**:`svchost.exe` の `ParentProcessName` が `services.exe`（または最初期ブートの `wininit.exe`）以外。本物の `svchost` は常に `services.exe` から生まれます。なりすましは目立ちます。
5. **改名されたバイナリ**:`NewProcessName` が無難な何か（`update.exe`、`svc.exe`、`data.exe`）で非標準パス。Sysmon 1 の `OriginalFileName` フィールドと組み合わせると、改名された PsExec や Mimikatz などを捕捉できます。

## サンプル Sigma ルール（Office → シェル）

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
  - Legitimate macros in Office add-ins running scripts
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## サンプル KQL / Splunk

KQL（Defender XDR / Sentinel、`SecurityEvent` 経由）:

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

Splunk:

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## ATT&CK マッピング

4688 検知カバレッジの大半は **T1059 — Command and Scripting Interpreter** とそのサブ技法（`.001` PowerShell、`.003` Windows Command Shell、`.005` Visual Basic、`.007` JavaScript）に属します。LOLBin パターンは **T1218 — System Binary Proxy Execution**（`.005` Mshta、`.010` Regsvr32、`.011` Rundll32）にマップ。Office → シェル連鎖は **T1566.001 — Phishing: Spearphishing Attachment** と T1059 の組み合わせに対応。改名バイナリ検知は **T1036.003 — Masquerading: Rename System Utilities** に該当します。

## 誤検知（アラート前に読んでください）

- **ソフトウェア更新エージェント**は正当にシェルを生成:Chocolatey、WinGet、ベンダ MSI ラッパ。ユーザー アカウントではなく、`SubjectUserSid`（LocalSystem）と安定した `ParentProcessName` パターンでホワイトリスト化。
- **脆弱性スキャナと EDR 製品**は攻撃者の偵察そっくりのプロセス ツリーを生成:net.exe、whoami.exe、systeminfo.exe。スキャナ IP / ホストにタグを付けて除外。
- **Citrix / RDS マルチセッション ボックス**はクロスドメイン アクセスのための正当な `runas /netonly` 連鎖を生成。パターンではなくユーザーを調査。
- **ログオン スクリプト**（`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`）はログオンごとに発火し、繰り返し連鎖として現れます。アラート前に特定してベースライン化。

## 4688 では分からないこと

ファイル ハッシュなし。`ParentCommandLine` なし。`ImageLoaded` なし（DLL インジェクションはプロセス作成ではない）。ネットワーク挙動なし。これらには [Sysmon イベント 1](/ja/blog/sysmon-event-id-1-process-create)（リッチな 4688）、Sysmon 7（イメージ ロード）、Sysmon 3/22（ネットワーク / DNS）、可能なら EDR の挙動データが必要です。4688 はプロセス可視性の最低限 — すべての Windows ホストが持つべき最小値です。重要なホストにおける適切な EDR + Sysmon の代替にはなりません。

## タイムラインにおける 4688 の位置

Sysmon なしのホストでの典型的な侵害後連鎖。

1. [**4624**](/ja/blog/understanding-event-id-4624) — 初期ログオン、外部 IP からの LogonType 3。
2. **4624** — 2 つ目のログオン、同じ `SubjectLogonId` 下の LogonType 9（`runas /netonly`） — 資格情報のピボット。
3. **4688** — そのセッション下の `powershell.exe -enc ...`。
4. [**4104**](/ja/blog/powershell-4104-scriptblock) — デコード済みスクリプト本体、2 段目ペイロードを取得。
5. **4688** — `%TEMP%` から実行される 2 段目バイナリ。
6. [**7045**](/ja/blog/service-creation-event-id-7045) — 永続化のためにインストールされたサービス。

6 つのレコードで物語全体が語られます。(3) と (5) の PID は 4688 の `ProcessId`/`NewProcessId` でつながりますが、Windows が PID をリサイクルするためタイムスタンプで検証してください。Sysmon があれば、`ProcessGuid` 連鎖が脆弱なマッチを置き換えます。

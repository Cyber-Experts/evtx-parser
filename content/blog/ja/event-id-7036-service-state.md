---
title: "Event ID 7036 を解説: DFIR トリアージのためのサービス状態変更"
description: "7036 はサービスの開始/停止のたびに発火します。7045 と組み合わせれば、永続化が実際に動いたかを確認できます。単独でもサービス濫用、防御回避、ブート異常を明らかにします。"
date: "2026-05-24"
---

Event ID **7036**「{service} サービスが {state} 状態に入りました」は、Service Control Manager がサービスの遷移を見るたびに [`System` チャネル](/ja/blog/what-is-an-evtx-file) に発火します。開始、停止、一時停止、再開ごとに 1 つ生成されます。単体では大量で見落とされやすいです。[7045](/ja/blog/service-creation-event-id-7045) と組み合わせれば、「バックドアがインストールされた」と「バックドアがインストールされ実行された」の違いです。

インシデント レスポンスにおいて、これは OS が与える最も安価な「実行されたか」のレコードです。

## どこに住むか

サービスが動いたホストの `System` チャネル。DC は関与せず、チャネル別転送の心配もなし。`System.evtx` にそのままあります。プロバイダー: `Service Control Manager`。

## レコードの中身

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

それだけ。2 つのパラメータとバイナリ タグ。多くの Security レコードよりずっと小さく、アナリストがスキップする理由です。

- `param1`。サービスの*表示名* (短い名前ではない)。ここでの `Background Intelligent Transfer Service` は `BITS` のユーザー向け名前です。サービス定義に軸を変えるには、通常短い名前が必要です。SCM はそれを UTF-16 blob として `Binary` に押し込みます (`42 00 49 00 54 00 53 00` は `BITS` にデコード)。
- `param2`。新しい状態: `running`、`stopped`、`paused`、`resumed`、または保留中の中間値 (`start pending`、`stop pending`)。`running` と `stopped` がほとんどのルールが鍵にするものです。

`AccountName` も `ImagePath` も `ProcessId` もありません。7036 は*何が*状態を変えたかを教えますが、*誰が*トリガーしたかは教えません。理由を得るには他のレコードと組み合わせます。

## 7036、7045、7035、7034: どれがどれ

System チャネルのサービス関連 4 イベントは常に混同されます:

| Event | いつ | 何をくれるか |
|---|---|---|
| **7045** | サービス インストール | 表示名、短い名前、`ImagePath`、`AccountName`、`StartType`。永続化点。 |
| **7036** | サービス開始/停止 | 表示名のみ。実行点。 |
| **7035** | サービス コントロール送信 | 誰が開始/停止を起動したか (SID)、何のコントロールが送信されたか。デフォルトでは on でないことが多い。 |
| **7034** | サービスが予期せずクラッシュ | クリーンな停止なしにサービスが終了。 |

パターンが重要です: 同じ表示名に対して 7045 の数秒後に `running` の 7036 は、教科書的な「インストールされ動いた」シーケンスです。一致する 7036 が*ない* 7045 は、サービスが登録されたが実行されなかったことを意味します: 攻撃者がクリーンアップしたか、インストーラーが中止したか、開始が延期されたかです。

数分以内に `running` の 7036 がない 7045 は、それ自体異常です。インストールが発火しなかった理由を調査してください。一般的な原因: 次回ブート用にステージングされた、手動開始に設定されていて攻撃者がまだトリガーしていない、開始失敗 (7034 / 7000 エラーを探す)。

### 防御回避: セキュリティ サービスを停止

最も悪用されるパターン。攻撃者が `WinDefend`、`MsMpEng`、`Sense`、`SecurityHealthService`、`EventLog`、`WdNisSvc`、または EDR 製品のサービスを停止します。それぞれが対応する表示名の `stopped` の 7036 を生成します。監査ポリシーや Defender の改ざんが試みられている場合、これは生き残るレコードの 1 つです。

アラートする価値のある名前 (表示名、Defender や EDR バージョンによって変わる):

- `Windows Defender Antivirus Service` -> `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` -> `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` -> `Sense`
- `Security Center` -> `wscsvc`
- `Windows Event Log` -> `EventLog`
- `*CrowdStrike*`、`*SentinelOne*`、`*Carbon*`、`*Cylance*`、`*Sophos*`、`*ESET*`、`*Symantec*` にマッチするもの

これらのいずれかに対する `stopped` の 7036、特にスケジュールされたメンテナンス ウィンドウ外、はハード アラートにすべきです。多くの攻撃者は `sc stop`、`net stop`、`Stop-Service`、`taskkill /im` を使います。すべて 7036 を生成します。

### サービス名のタイポスクワッティング

7036 は表示名で発火します。基底のサービスが悪意のあるものであってもです。正当に見えるが、インストールされた Microsoft サービスにマッチしない表示名に注意してください: `Windows Update Service` (実名は `Windows Update`)、`Windows Defender Service` (実名は `Windows Defender Antivirus Service`)、`Microsoft Telemetry` (そんなサービスはない)。既知の良いホストから表示名のベースラインを取り、差分してください。

### ブート異常

再起動後、SCM はおおむね安定した順序で自動開始サービスを上げます。ブート 7036 シーケンスに新規自動開始サービスが現れる、特に前回ブートになかったものは、新規永続化点です。前回シャットダウン以前の対応する 7045 と相互参照してください。

## Sigma: セキュリティ サービスが停止された

```yaml
title: Security Service Stopped via 7036
id: 1d0b3a3a-94a4-44f7-9d29-3c0fbf2c9a91
status: stable
description: A security/defense service transitioned to the stopped state.
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7036
    param2: 'stopped'
  defender:
    param1|contains:
      - 'Windows Defender'
      - 'Microsoft Defender'
      - 'Microsoft Monitoring'
      - 'Windows Event Log'
      - 'Security Center'
      - 'CrowdStrike'
      - 'SentinelOne'
      - 'Carbon Black'
      - 'Cylance'
      - 'Sophos'
      - 'ESET'
      - 'Symantec'
  condition: selection and defender
falsepositives:
  - Scheduled maintenance windows
  - Vendor uninstall / upgrade workflows
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

## KQL: 7045 から 7036 のシーケンス

主軸のピボット。同じホストで永続化インストール後 5 分以内に実行:

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]),
              AccountName=tostring(XmlData.EventData.Data[3]["#text"]);
Event
| where Source == "Service Control Manager" and EventID == 7036
| extend XmlData = parse_xml(EventData)
| where tostring(XmlData.EventXML.param2) == "running"
| project RunTime=TimeGenerated, Host=Computer,
          DisplayName=tostring(XmlData.EventXML.param1)
| join kind=inner (installs) on Host
| where RunTime between (InstallTime .. InstallTime + 5m)
| project InstallTime, RunTime, Host, ServiceName, DisplayName, ImagePath, AccountName
| order by InstallTime desc
```

7036 の `DisplayName` は 7045 の `ServiceName` と常に文字通り等しいわけではありません (一方は表示、もう一方は短縮)。発見的にマッチさせるか、重要なサービスの小集合のためのマップを事前に計算してください。

## Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## ATT&CK マッピング

- T1562.001 Impair Defenses: Disable or Modify Tools。セキュリティ サービスの 7036 `stopped`。
- T1543.003 Create or Modify System Process: Windows Service。同じサービスの 7045 とペアの 7036 `running`。
- T1569.002 System Services: Service Execution。非標準バイナリを指す `ImagePath` の 7036 `running`、しばしばラテラル ムーブメントの一部 (PsExec、SCM ベースのリモート実行、Impacket `psexec.py`)。
- T1489 Service Stop。可用性をターゲット (データベース暗号化前に SQL Server を停止するランサムウェア)。

## 攻撃と見分けがつかない誤検知

- Windows Update は予測可能なシーケンスで十数のサービスを再起動します。繰り返しで素早い。
- Defender 署名更新は `WinDefend` 自体を再起動することがあります。`MsSecFlt.exe` からの `stopped` の後すぐ `running` が通常パターン。悪意あるのは `stopped` の後 `running` が*ない*こと。
- EDR アップグレードは EDR サービスを停止して再起動します。ベンダーのアップグレード ウィンドウにタグを。
- システム スリープとハイバネートは、スリープ時の `stopped` バッチと起動時の `running` バッチを生成します。これらを単独でアラートしないでください。
- コンテナと Hyper-V ワークロードは常にサービスを上下させます。

## 7036 が教えないこと

- `AccountName` なし。対応する 7045 または SCM データベースから取得してください。
- PID なし。7036 を直接 [4688](/ja/blog/event-id-4688-process-creation) または [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) レコードにマップするには `ImagePath` とタイムスタンプで相関する必要があります。4688 が off だったときは [prefetch](https://www.prefetchparser.com) キャッシュが二次裏付けです。
- 開始元なし。Stop-Service を呼んだのが誰かは見えません。それには 7035 (デフォルトでは無効が多い)、呼び出した `net stop` / `sc stop` / `taskkill` のための [4688](/ja/blog/event-id-4688-process-creation)、または `Stop-Service` のための [4104](/ja/blog/powershell-4104-scriptblock) が必要です。
- サービス短縮名のマッピング。表示名は `param1` にあります。短縮名はバイナリ blob にあり、デコードする必要があります。多くのパーサーは自動でやります。生 `EventData` をクエリする場合、自分で処理する必要があります。

## タイムラインでの 7036 の位置

ラテラル実行と防御回避:

1. [4624](/ja/blog/understanding-event-id-4624)。攻撃者制御ホストからの LogonType 3、AuthenticationPackage Kerberos。
2. [4688](/ja/blog/event-id-4688-process-creation)。`services.exe` が SCM 操作のために子を生む (または PsExec の `psexesvc.exe`)。
3. [7045](/ja/blog/service-creation-event-id-7045)。サービス インストール、標準インストール パス外の `ImagePath`。
4. **7036 `running`**。インストールが実際に発火。実行確認。
5. `WinDefend` または EDR の **7036 `stopped`**。ペイロード実行前の防御回避。
6. [4688](/ja/blog/event-id-4688-process-creation)。サービス アカウント下のペイロード プロセス。
7. インストーラー サービスの **7036 `stopped`**。クリーンアップ。

7036 はステップ 4、5、7 に現れます。同じ侵入の 3 つの異なる段階。単独では使いにくい。文脈の中では、永続化レコード (7045) を実際の実行と、周囲の防御回避アクションにつなげます。

## 参考資料

- [Microsoft ドキュメント: 7036](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7036)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)

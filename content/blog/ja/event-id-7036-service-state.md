---
title: "Event ID 7036 を解読する:DFIR トリアージのためのサービス状態変化"
description: "7036 はサービスの起動 / 停止のたびに発火。7045 と組み合わせれば永続化が実際に動いたかを確認でき、単体でもサービス不正利用、防御回避、起動異常を明かす。"
date: "2026-05-24"
---

Event ID **7036** — 「{service} サービスは {state} 状態に入りました」 — は、Service Control Manager（SCM）がサービスの遷移を検知するたびに [`System` チャネル](/ja/blog/what-is-an-evtx-file) に発火します。各サービスの起動、停止、一時停止、再開がそれぞれ 1 件を生成します。単体ではボリュームが高く軽視されがちですが、[7045](/ja/blog/service-creation-event-id-7045)（サービス インストール）と組み合わせると、*バックドアがインストールされた*と*バックドアがインストールされて動いた*の差を分けます。

インシデント対応にとって、これは OS が与える最も安価な「実行されたか?」レコードです。

## どこに記録されるか

サービスが動いたホストの**`System` チャネル**に常に記録されます。DC の関与なし、チャネル単位の転送を心配する必要もなし — `System.evtx` にそのまま存在します。プロバイダは `Service Control Manager`。

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

これだけです。2 つのパラメータとバイナリ タグ — ほとんどの Security レコードよりずっと小さく、これがアナリストがスキップする理由です。

- **`param1`** — サービスの*表示名*（短名ではありません）。ここの `Background Intelligent Transfer Service` は `BITS` のユーザー向け名前。サービス定義にピボットするには短名が必要なことが多く、SCM は `Binary` にも UTF-16 エンコードされたブロブとして書き込みます（ここの `42 00 49 00 54 00 53 00` は `BITS` にデコード）。
- **`param2`** — 新しい状態:`running`、`stopped`、`paused`、`resumed`、または一握りの保留中間状態（`start pending`、`stop pending`）。ほとんどのルールがキーにするのは `running` と `stopped` の遷移。

`AccountName`、`ImagePath`、`ProcessId` はありません — 7036 は*何が*状態を変えたかを伝え、*誰が*変更をトリガーしたかは伝えません。理由を得るには他のレコードと組み合わせます（下記参照）。

## 7036 vs 7045 vs 7035 vs 7034

4 つのサービス関連 System チャネル イベントが常に混同されます。

| イベント | いつ | 何が得られるか |
|---|---|---|
| **7045** | サービス インストール | 表示名、短名、`ImagePath`、`AccountName`、`StartType`。永続化点。 |
| **7036** | サービス起動 / 停止 | 表示名のみ。実行点。 |
| **7035** | サービス制御送信 | 起動 / 停止を開始した者（SID）、送信された制御。デフォルトでは滅多にオンでないが、オンなら価値あり。 |
| **7034** | サービスが予期せずクラッシュ | クリーンな停止なしに終了したサービス。回復アクション。 |

パターンが重要です:**7045 の数秒後に同じ表示名の 7036 `running` が続くのが教科書的な「インストールされて動いた」シーケンス。** マッチする 7036 が*ない* 7045 は、サービスは登録されたが実行されなかったことを意味します — 攻撃者がクリーンアップした、インストーラが中断した、または起動が延期された。

数分以内に 7036 `running` のない 7045 はそれ自体が異常 — インストールが発火しなかった理由を調査。一般的な原因:インストーラが次回再起動用にステージングされている、サービスが手動起動に設定され攻撃者がまだトリガーしていない、起動が失敗（7034 / 7000 エラーを探す）。

## トリアージ パターン

### 1. 永続化検証 — 7045 と組み合わせ

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

3 つのレコード、1 つの PsExec 横展開実行イベント。7036 のペアは、サービスが実際に動いた（インストールされただけでない）ことを伝えます。*永続的な*バックドアでは、2 つ目の 7036（stopped）は欠けているか、ホストが再起動する数時間 / 数日後に現れるかもしれません。

数分以内に 7036 `running` がない 7045 は、それ自体が異常 — なぜインストールが発火しなかったか調査。一般原因:インストーラが次回起動向けにステージング、サービスが手動起動に設定されまだトリガーされていない、起動失敗（7034 / 7000 エラーを探す）。

### 2. 防御回避シグナル — セキュリティ サービスの停止

最も悪用されるパターン:攻撃者が `WinDefend`、`MsMpEng`、`Sense`、`SecurityHealthService`、`EventLog`、`WdNisSvc`、または EDR 製品のサービスを停止する。それぞれが対応する表示名の 7036 `stopped` を生成します。監査ポリシー / Defender の改ざんが試みられているなら、これは生き残るレコードの 1 つです。

アラートすべき名前（表示名。Defender / EDR のバージョンで異なる）。

- `Windows Defender Antivirus Service` → サービス `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` → `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` → `Sense`
- `Security Center` → `wscsvc`
- `Windows Event Log` → `EventLog`
- `*CrowdStrike*`、`*SentinelOne*`、`*Carbon*`、`*Cylance*`、`*Sophos*`、`*ESET*`、`*Symantec*` のいずれかにマッチするもの

これらに対する 7036 `stopped` — 特にスケジュールされたメンテナンス ウィンドウ外 — はハード アラートにすべき。多くの攻撃者は `sc stop`、`net stop`、`Stop-Service`、`taskkill /im` を使う — 4 つすべて 7036 を生成します。

### 3. サービス名のタイポスクワット

7036 は背後のサービスが悪意でも表示名で発火します。正当に見えるが実際にはインストールされた Microsoft サービスにマッチしない表示名に注意:`Windows Update Service`（実名は `Windows Update`）、`Windows Defender Service`（実名は `Windows Defender Antivirus Service`）、`Microsoft Telemetry`（そのようなサービスは存在しない）。既知の良好なホストの表示名ベースラインを取り、diff してください。

### 4. ブート異常

再起動後、SCM は自動起動サービスをほぼ安定した順序で立ち上げます。ブート 7036 シーケンスに現れる新しい自動起動サービス — 特に前回ブートにはなかったもの — は新しい永続化点です。前回シャットダウン以前のマッチする 7045 とクロスリファレンス。

## サンプル Sigma ルール — セキュリティ サービス停止

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

## サンプル KQL — 7045 → 7036 シーケンス

目玉のピボット。同じホスト上で 5 分以内にインストールに続く実行。

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

7036 の `DisplayName` は常に文字通り 7045 の `ServiceName` と等しいわけではありません（一方は表示名、一方は短名） — ヒューリスティックにマッチさせるか、重要なサービスの小集合についてマップを事前計算してください。

## サンプル Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## ATT&CK マッピング

- **T1562.001 — Impair Defenses: Disable or Modify Tools**:セキュリティ サービスへの 7036 `stopped`。
- **T1543.003 — Create or Modify System Process: Windows Service**:同じサービスの 7045 と組み合わさった 7036 `running`。
- **T1569.002 — System Services: Service Execution**:非標準バイナリを指す `ImagePath` の 7036 `running`。横展開（PsExec、SCM ベースのリモート実行）の一部であることが多い。
- **T1489 — Service Stop**:可用性を標的に — 他のアクションを可能にするためにサービスを停止（ランサムウェアがデータベース暗号化前に SQL Server を停止）。

## 攻撃そっくりの誤検知

- **定例の Windows Update** は予測可能なシーケンスで一連のサービスを再起動。パターンは繰り返しで素早い。
- **Defender 定義更新**は時に `WinDefend` 自体を再起動 — `stopped` の後すぐに `MsSecFlt.exe` からの `running` が通常パターン。悪意のあるパターンは `stopped` 後に `running` が*ない*。
- **EDR アップグレード**は EDR サービスを停止して再起動。ベンダのアップグレード ウィンドウにタグ。
- **システム スリープ / 休止**はスリープ時に `stopped` レコード、復帰時に `running` レコードのバッチを生成。`wake source` イベントと組み合わせると明白 — 単独でアラートしないように。
- **コンテナ / Hyper-V** ワークロードは絶えずサービスを上下させる。

## 7036 では分からないこと

- **`AccountName` なし**:レコードはサービスが動いているセキュリティ コンテキストを伝えません。マッチする 7045 または SCM データベースから取得してください。
- **PID なし**:`ImagePath` とタイムスタンプで相関させない限り、7036 を [4688](/ja/blog/event-id-4688-process-creation) / [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) レコードに直接マップできません。
- **開始者なし**:Stop-Service を呼んだ*者*は見えません。それには 7035（デフォルトでは無効が多い）、呼び出し元の `net stop` / `sc stop` / `taskkill` に対する [4688](/ja/blog/event-id-4688-process-creation)、または `Stop-Service` に対する [4104](/ja/blog/powershell-4104-scriptblock) が必要です。
- **サービス短名マッピング**:表示名は `param1`、短名はバイナリ ブロブにあり、デコードが必要。ほとんどのパーサは自動で行います。生 `EventData` をクエリするなら自分で扱う必要あり。

## タイムラインにおける 7036 の位置

横展開実行 + 防御回避のコンボ。

1. [**4624**](/ja/blog/understanding-event-id-4624) — 攻撃者制御ホストからの LogonType 3、AuthenticationPackage Kerberos。
2. [**4688**](/ja/blog/event-id-4688-process-creation) — SCM 操作のために子をスポーンする `services.exe`（または PsExec の `psexesvc.exe`）。
3. [**7045**](/ja/blog/service-creation-event-id-7045) — サービス インストール、`ImagePath` が標準インストール パスの外。
4. **7036** `running` — インストールが実際に発火。**ここが実行確認。**
5. **7036** `stopped` `WinDefend` / EDR について — ペイロードが動く前の防御回避。
6. [**4688**](/ja/blog/event-id-4688-process-creation) — サービス アカウント下のペイロード プロセス。
7. **7036** `stopped` インストーラ サービスについて — クリーンアップ。

7036 はステップ 4、5、7 に現れる — 同じ侵入の 3 つの異なるステージ。単独では使いにくいが、文脈の中では永続化レコード（7045）を実際の実行と周辺の防御回避アクションに結びつけます。

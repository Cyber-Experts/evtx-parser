---
title: "Event ID 1102 を解読する:セキュリティ監査ログのクリア（と残るもの）"
description: "1102 は、より多くの証拠を残さずには抑制できない唯一のイベント。何を伝え、クリア後も何が残るのかを解説。"
date: "2026-05-17"
---

Event ID **1102** は、監査ログがクリアされたときに Windows が [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に書き込むレコードです。設計上、攻撃者にとって最も抑制が困難なレコードの 1 つです。抑制するには、EventLog サービスを起動前に置き換えに成功するか、クリアの行為自体が 1102 を残してしまうことを受け入れるかしかありません。

ディフェンダーにとってこれは:1102 が見えたら、十分な特権を持つ誰かが故意に監査の証跡を消したということです。これは通常の管理操作ではほぼあり得ません。

## レコードの中身

```xml
<UserData>
  <LogFileCleared>
    <SubjectUserSid>S-1-5-21-1234-...-500</SubjectUserSid>
    <SubjectUserName>Administrator</SubjectUserName>
    <SubjectDomainName>CORP</SubjectDomainName>
    <SubjectLogonId>0x3e7</SubjectLogonId>
  </LogFileCleared>
</UserData>
```

通常の `EventData` ではなく `UserData` ブロックである点に注目してください — 1102 は構造化されたユーザー データ スキーマを使うレコードの 1 つです。フィールドは、*どのログオン セッションの下で、誰が*ログをクリアしたかを示します。`SubjectLogonId` でピボットして対応する [4624](/ja/blog/understanding-event-id-4624) を見つければ、その特権セッションを生んだ送信元 IP とログオン タイプが分かります。

## 1102 と一緒に発火するもの

ログ クリアが*唯一*の反フォレンジック行動であることは稀です。よく伴う仲間を、おおよその時系列で。

- `System` チャネルの **104** — 同じ行為が SCM によって記録されたもの。104 はあるが 1102 がない場合、攻撃者は Security ログだけクリアして System を忘れたということ。
- **4719** — 「システム監査ポリシーが変更されました」。次のラウンドでレコードを少なくするため、クリアの*前に*監査範囲を縮小することがあります。
- **4616** — 「システム時刻が変更されました」。クリア前の時刻スキューはタイムライン再構築を困難にします。
- 1102 の前 1〜2 時間の **4624 のギャップ** — 攻撃者が記録されないサイド チャネルを使った可能性。

## クリアでも残るもの

メモリ上のイベント ログをクリアしても、以下には影響しません。

- **他のチャネル**:`System`、`Application`、`PowerShell/Operational`、`Sysmon/Operational`、`TaskScheduler/Operational`、転送イベント チャネル — どれも Security のクリアでは消えません。
- **転送イベント**:Windows Event Forwarding（WEF）で中央コレクタに設定されていれば、クリアされたレコードはすでに別のホストに存在します。
- **ディスク上のファイル自体**:クリアされた `Security.evtx` は新しいファイルに置き換えられます。*削除された*以前のファイルのクラスタは未割り当て領域に残っていることが多く、NTFS ツールでカービング可能です。
- ファイル置き換えに伴う **USN ジャーナル エントリ**:クリア操作自体がファイルシステム レベルのアーティファクトを残します。

「成功した」ログ クリアは、攻撃者が望むほどクリーンには終わらないことが多いのです。

## サンプル Sigma ルール — ログ クリア

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared) — anti-forensic actions.
references:
  - https://attack.mitre.org/techniques/T1070/001/
logsource:
  product: windows
  service: security
detection:
  selection_security:
    EventID: 1102
    Provider_Name: 'Microsoft-Windows-Eventlog'
  selection_system:
    EventID: 104
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: selection_security or selection_system
falsepositives:
  - Legitimate administrative log clearing during maintenance (rare, should be ticketed)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

承認されたメンテナンス枠の外で 1102 が見えたら、インシデントとして扱ってください — それだけです。

## サンプル KQL — ログ クリアと特権セッションの相関

```kusto
let clears =
    SecurityEvent
    | where EventID == 1102
    | project ClearTime=TimeGenerated, Host=Computer, ClearLogonId=SubjectLogonId,
              ClearUser=SubjectUserName;
let privileged =
    SecurityEvent
    | where EventID == 4672
    | project PrivTime=TimeGenerated, PrivLogonId=SubjectLogonId,
              PrivilegeList;
clears
| join kind=inner privileged on $left.ClearLogonId == $right.PrivLogonId
| project ClearTime, Host, ClearUser, PrivTime, PrivilegeList
| order by ClearTime desc
```

すべての 1102 は、`SeSecurityPrivilege` を付与した [4672](/ja/blog/event-id-4672-special-privileges) に遡り、それはさらに [4624](/ja/blog/understanding-event-id-4624) に遡ります。join により全体像が完成します。

## サンプル Splunk — 反フォレンジック連鎖

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

監査ポリシー（4719）またはシステム時刻（4616）に手を加え、その後でログをクリア（1102/104）した `LogonId` が、改ざんの連鎖です。

## ATT&CK マッピング

- **T1070.001 — Indicator Removal: Clear Windows Event Logs**:目玉の技法。1102 はこの技法の主要指標そのもの。
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**:4719（監査ポリシー変更）が 1102 に先行するケースが該当。
- **T1070.006 — Indicator Removal: Timestomp**:同じ連鎖で 4616（システム時刻変更）と組み合わさる。
- **T1078.003 — Valid Accounts: Local Accounts**:本来その時刻にログオンするはずのないローカル Administrator による 1102。

## 誤検知 — 稀だが現実に存在

- **移行 / 廃止ワークフロー**:廃止予定ホストでログをクリアする技術者。常にチケット化されているべき。
- **フォレンジック / テスト ラボ**:検知開発中の clear-and-reproduce ワークフロー。
- **一部レガシー ツール**はベースラインをリセットするためにログをクリアします — ほぼ常に手続きミスですが、実在します。

シグナルは直接的に反フォレンジック的なので、正当な 1102 であっても事後に必ず調査し記録すべきです。通常運用で 1102 が出る「安全な」理由はありません。

## パーシングにおける意味

[.evtx ファイルをフォレンジック ツールに読み込んだら](/ja/blog/how-to-open-an-evtx-file)、*最初に*走らせる価値のある検索は `EventID:1102` と `EventID:104` です。どちらかが存在すれば、手にしているログには既知のギャップがあり、そこから組み立てるタイムラインは不完全です。レポートに目立つように記載してください。

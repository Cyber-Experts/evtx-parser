---
title: "Event ID 1102 を解説: Security 監査ログのクリア (と残るもの)"
description: "1102 は、より多くの証拠を残さずに抑制できない唯一のイベントです。それが何を告げるか、クリアを生き残るもの、目にしたあとどこを見るかを解説します。"
date: "2026-05-17"
---

Event ID **1102** は、誰かが監査ログをクリアしたときに Windows が [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に書き込むレコードです。設計上、攻撃者が抑制しにくいレコードの 1 つです。きれいに抑制するには、起動前に EventLog サービス バイナリを置き換えるか、クリアという行為自体が独自の 1102 を残すことを受け入れる必要があります。多くのオペレーターは、誰も注目していないことを願って 2 つ目を選びます。

1102 を見たら、十分な特権を持つ誰かが意図的に監査証跡を消したということです。これは通常の管理者作業ではほぼあり得ず、もしそうであればチケット起票されているはずです。承認済みメンテナンス時間外のすべての 1102 は、否定されるまではインシデントとして扱ってください。

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

通常の `EventData` ではなく `UserData` ブロックである点に注意。1102 は構造化された user-data スキーマを使うため、`EventData` しか見ない素朴なパーサーをつまずかせます。フィールドは、どの logon セッションの誰がログをクリアしたかを教えます。`SubjectLogonId` を軸に対応する [4624](/ja/blog/understanding-event-id-4624) に飛べば、その特権セッションを生んだ送信元 IP、ログオン タイプ、資格情報が得られます。

## 一緒に走るもの

ログ クリアが連鎖中で唯一のアンチフォレンジック行動であることはまずありません。近くで発火しがちなレコードを、おおまかな時系列で:

- `System` チャネルの **104**。1102 と同じ行為ですが、Security 以外のチャネルについて SCM が記録します。104 があって 1102 がない場合、攻撃者は Security だけクリアし System を忘れたのです。
- **4719**、「システム監査ポリシーが変更されました」。次回以降に残るレコードを減らすため、クリア前に監査範囲を狭めることがあります。
- **4616**、「システム時刻が変更されました」。クリア前のタイムスタンプ改ざんは、タイムライン再構築を難しくします。
- 1102 の 1〜2 時間前の 4624 のギャップ。攻撃者がログに残らないサイド チャネルで侵入した可能性があります。

## クリアを生き残るもの

メモリ上のイベント ログをクリアしても、次のものは触れられません:

- 他のチャネル。`System`、`Application`、`PowerShell/Operational`、`Sysmon/Operational`、`TaskScheduler/Operational`、転送イベント チャネル。これらは Security のワイプではクリアされません。
- 転送されたイベント。Windows Event Forwarding が Security をコレクターに送っているなら、クリアされたレコードは既に別ホスト上にあります。元の RecordID とタイムスタンプは保持されます。
- ディスク上のファイル自体。クリアされた `Security.evtx` は新しいファイルに置き換えられます。前のファイルのクラスタはしばしば未割り当てに残ります。EVTX レコードはそこから[綺麗にカービング](/ja/blog/carve-deleted-evtx-records) できます。
- ファイル置き換えの [USN journal](https://www.usnparser.com) エントリ。クリアという行為自体がファイルシステム レベルのアーティファクトを残します。
- 新ファイルの [MFT](https://www.mftparser.com) エントリ。作成タイムスタンプは 1102 と秒単位で一致するはずです。

「成功した」ログ クリアは、攻撃者が期待するほど綺麗ではないことがほとんどです。

## Sigma: ログ クリア

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared). Anti-forensic actions.
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

## KQL: 特権セッションと相関したクリア

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

すべての 1102 は `SeSecurityPrivilege` を付与する [4672](/ja/blog/event-id-4672-special-privileges) に遡り、それは [4624](/ja/blog/understanding-event-id-4624) に遡ります。ジョインで全体像が完成します。

## Splunk: 改ざんチェーン

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

監査ポリシー (4719) またはシステム時刻 (4616) に触れ、その後ログをクリア (1102/104) した LogonId は、改ざんチェーンです。

## ATT&CK マッピング

- T1070.001 Indicator Removal: Clear Windows Event Logs。見出しです。1102 が主要なインジケータ*そのもの*です。
- T1562.002 Impair Defenses: Disable Windows Event Logging。1102 に先行する 4719 がここに対応します。
- T1070.006 Indicator Removal: Timestomp。同じチェーンで 4616 と組み合わせ。
- T1078.003 Valid Accounts: Local Accounts。当時ログオンしているべきでないローカル Administrator による 1102。

## 稀ではあるが実在する誤検知

- 移行や撤去のワークフロー。撤去中のホストでログをクリアする技術者。常にチケット起票すべき。
- 検知開発中に clear-and-reproduce ループを回すフォレンジック ラボ。
- 一部のレガシー ツールは「ベースラインをリセット」するためにログをクリアします。ほぼ常に手順上のミスですが、実在します。

通常運用で 1102 が出る安全な理由はありません。正当なケースであっても、事後に調査・文書化すべきです。

## バンドルで 1 つ見つけたとき

[フォレンジック ツールに .evtx ファイルをロード](/ja/blog/how-to-open-an-evtx-file) したら、最初に走らせる価値のある 2 つの検索は `EventID:1102` と `EventID:104` です。どちらかでも存在すれば、手元のログには既知のギャップがあります。そこから組み立てるタイムラインはすべて不完全です。報告書に大きく書いてください。それから生き残ったものを見に行きます: [registry](https://www.registryparser.com)、[USN journal](https://www.usnparser.com)、[MFT](https://www.mftparser.com)、[prefetch](https://www.prefetchparser.com)、[AmCache](https://www.amcacheparser.com)。これらが、1102 が消そうとしたものの大半を再構築します。

`Invoke-Phant0m` のようなツールはクリアではなくイベント サービスのスレッドを停止するため、1102 を完全にスキップします。Security に数時間の沈黙があり、1102 もシステム シャットダウンもないなら、同じ問題の別の形です。

## 参考資料

- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [1102 の Microsoft ドキュメント](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)

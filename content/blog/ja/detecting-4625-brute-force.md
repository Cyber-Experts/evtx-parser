---
title: "Event ID 4625 を解説: ブルートフォース、スプレー、列挙の検出"
description: "4625 はログオン失敗レコードです。正しく読めば、成功に転じる前にパスワード スプレー、クレデンシャル スタッフィング、Kerberos の悪用を見つけられます。"
date: "2026-05-17"
---

Event ID 4625「アカウントがログオンに失敗しました」は、認証試行が拒否されるたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に発火します。クレデンシャル攻撃を進行中に捕まえるうえで最も有用なレコードです。同時に、見出しメッセージが汎用的で、答えがフィールド 2 つぶん深くにあるために、アナリストが最も誤読しやすいレコードでもあります。

## 判断を決めるフィールド

典型的なレコード:

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
```

`Status` と `SubStatus` を合わせて読むことで、ログオンが失敗した理由が分かります。実際に気にすべきペアは `SubStatus` です。覚えておくべきコード:

- `0xC0000064`: アカウントが存在しない。ユーザー名列挙。
- `0xC000006A`: パスワード違い。古典的なもの。
- `0xC0000234`: アカウントがロックアウトされた。
- `0xC0000072`: アカウントが無効化されている。
- `0xC0000071`: パスワードの有効期限切れ。
- `0xC0000133`: Kerberos の時刻ずれ。AS-REP roasting 試行でホストの時刻を偽装したときによくあります。
- `0xC000018B`: SID が違う。ワークステーションが自分のドメインを誤認識している。稀で興味深い。

有効と無効のユーザー名が混じった `0xC0000064` のバーストは偵察です。1 アカウントに対する `0xC000006A` のバーストはブルートフォースです。多数アカウントに対して*同じ*パスワードで試す `0xC000006A` のバーストはスプレーです。同じイベント ID、3 つの異なるインシデントです。

## 本領を発揮するトリアージ クエリ

1. スプレー検知。4625 を `IpAddress` (IP フィールドが空なら `WorkstationName`) でグループ化し、10 分間にわたるユニークな `TargetUserName` の数を数える。そのウィンドウで送信元あたり 5 アカウント超は、ほぼどこでも怪しい。
2. ブルートフォース。`TargetUserName` でグループ化し、分あたりの失敗数を数える。1 アカウントに対して分あたり 10 回超は、ほぼ自動化されています。
3. ロックアウトの根本原因。4740 (アカウント ロック) を先行する 4625 と組み合わせる。`WorkstationName` フィールドがロックアウトを引き起こしたデバイスを教えてくれます。多くの場合、攻撃者ではなく古いキャッシュ資格情報を持つドメイン参加サーバーです。ヘルプデスクは両者を同じように扱い、SOC はどちらをエスカレートするか決めなければならないので、トリアージが重要になります。

## 「その後」が対応を決める

同じ `IpAddress` からの 4625 バーストの後に [4624](/ja/blog/understanding-event-id-4624) が続くのが、行動すべきケースです。攻撃者が動く資格情報を見つけました。タイムラインでの進行は紛れもありません: 密な失敗、突然の沈黙、単一の成功。

## Sigma: パスワード スプレー

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window. The password-spray fingerprint.
references:
  - https://attack.mitre.org/techniques/T1110/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 10m
falsepositives:
  - Misconfigured service account on a host hitting many endpoints
  - Vulnerability scanner authentication probes (tag scanner IPs)
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
```

## KQL: 単一アカウントに対するブルートフォース

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk: 列挙からブルートへの移行

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

信号は*進行*そのものです: まず列挙で有効ユーザー名を見つけ、次に標的を絞ったパスワード試行。新しいユーザー リストを持った実オペレーターは、両方の形を数分以内に生み出します。

## ATT&CK マッピング

- T1110.001 Brute Force: Password Guessing。単一アカウントへの多数の `0xC000006A` 失敗。
- T1110.003 Brute Force: Password Spraying。多数アカウント、1 つの送信元、各々の失敗は少数。
- T1110.004 Credential Stuffing。多数アカウント、1 つの送信元、`0xC0000064` (アカウント不在、漏洩リストの外れ) と `0xC000006A` (命中) の混在。
- T1078 Valid Accounts。同じ送信元から 4625 バースト後に [4624](/ja/blog/understanding-event-id-4624) 成功。侵害です。
- T1556 Modify Authentication Process。異常な `LogonProcessName` (`User32`、`NtLmSsp`、`Kerberos`、`Advapi`、`Schannel` 以外) は改ざんを示唆します。

## 衣装を着た誤検知

- パスワード変更後に古くなった保存資格情報。ユーザーのマップ ドライブ、スケジュールド タスク、サービス設定が古いパスワードで再試行します。形は 1 つの `TargetUserName`、1 つの `IpAddress`、安定した `0xC000006A` の頻度。アラートを出す前に、古い資格情報を持つホストを見つけて修正してください。
- 構成ミスの自動化。間違ったパスワードでループ リトライするスクリプト。ブルートフォースと同じ形。まずオーナーに話してください。
- 認証スキャン中の脆弱性スキャナーは密な 4625 トラフィックを生成します。スキャナー IP にタグを付けてください。
- ロックアウト ポリシーのチャーン。積極的にロック解除するヘルプデスク手順は、繰り返す 4625 → 4740 → 4624 のサイクルを生みます。煩わしい。悪意はない。

## 4625 が隠すもの

DC を通る Kerberos と NTLMv2 の失敗は、有用な `IpAddress` を常に運ぶわけではありません。フィールドは空または `-` になることがあります。それらについては、DC のレコード ([4768](/ja/blog/event-id-4768-kerberos-tgt) と Kerberos pre-auth 失敗の 4771) に軸を変えてください。「送信元 IP がなければ調査なし」は誤った直感です。代わりに DC ログを見てください。

`LogonProcessName` と `AuthenticationPackageName` フィールドは、どの認証スタックが試行を処理したかを教えます。有用な値: `NtLmSsp` (NTLM)、`Kerberos`、`Negotiate` (どちらかを選ぶ)、`User32` (ローカル コンソール)、`Schannel` (TLS バックアップ)。それ以外はもっとよく見てください。

## 参考資料

- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)

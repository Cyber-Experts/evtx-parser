---
title: "Event ID 4625 を解読する:ブルートフォース、スプレー、列挙の検知"
description: "4625 はログオン失敗のレコード。正しく読めば、成功する前にパスワード スプレー、クレデンシャル スタッフィング、Kerberos 不正利用を捕捉できる。"
date: "2026-05-17"
---

Event ID 4625 — 「アカウントがログオンに失敗しました」 — は、認証試行が拒否されるたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に記録されます。クレデンシャル攻撃活動を捕捉するうえで単体で最も有用なレコードですが、それは正しいフィールドを読めればの話です。

## 実際に重要なフィールド

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
```

`Status` と `SubStatus` の組み合わせが、ログオンが失敗した*理由*を教えてくれます。

- `0xc0000064` — アカウントが存在しない（ユーザー名列挙）。
- `0xc000006a` — パスワード違い（教科書的）。
- `0xc0000234` — アカウント ロックアウト。
- `0xc0000072` — アカウント無効化。
- `0xc0000071` — パスワード期限切れ。
- `0xc0000133` — Kerberos チケットのクロック スキュー（AS-REP roasting 時によく見られる）。
- `0xc000018b` — SID 違い — ワークステーションが自分が思っているドメインに属していない。

有効・無効を問わないユーザー名に対する `0xc0000064` の連発は偵察。1 つのアカウントに対する `0xc000006a` の連発はブルートフォース。複数アカウントに対して*同じパスワード*での `0xc000006a` の連発はパスワード スプレーです。

## パターン

最もシンプルなトリアージ クエリ。

1. **スプレー検出**:4625 を `IpAddress`（IP が記録されていなければ `WorkstationName`）でグルーピングし、10 分間に対する distinct な `TargetUserName` を数える。同じウィンドウで送信元あたり 5 を超えるアカウントなら、ほぼどこでも不審。
2. **ブルートフォース**:`TargetUserName` でグルーピングし、1 分あたりの失敗数を数える。1 つのアカウントに対して毎分 10 を超えるならボットの可能性大。
3. **ロックアウトの根本原因**:4740（アカウントがロックアウト）と先行する 4625 群を組み合わせる — `WorkstationName` フィールドがロックアウトを引き起こしたデバイスを示します。これは重要で、攻撃者ではなくドメイン参加サーバに古いパスワードが保存されているケースが多いからです。

## 「あと」も「まえ」と同じくらい大事

4625 の連発の直後に同じ `IpAddress` から [4624](/ja/blog/understanding-event-id-4624) が来るのが actionable なケースです — 攻撃者が有効なクレデンシャルを見つけたということ。本ページのパーサーでは、テーブルを送信元 IP でフィルタリングし、タイムラインでレベルとイベント ID の推移を時間軸で観察できます。連発の後にスパイクが来るパターンは間違いようがありません。

## サンプル Sigma ルール — パスワード スプレー

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window — the password-spray fingerprint.
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

## サンプル KQL — 単一アカウントへのブルートフォース

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## サンプル Splunk — ブルート前の列挙

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

シグナルは*進行*にあります — 有効なユーザー名を見つけるための列挙、続いてそれに対するブルートフォース。

## ATT&CK マッピング

- **T1110.001 — Brute Force: Password Guessing**:単一アカウント、多数の `0xC000006A` 失敗。
- **T1110.003 — Brute Force: Password Spraying**:多数アカウント、アカウントあたり数回の失敗、単一送信元。
- **T1110.004 — Brute Force: Credential Stuffing**:多数アカウント、単一送信元、漏洩リストの外れに対する `0xC0000064`（アカウント不存在）が `0xC000006A` のヒットに混ざる。
- **T1078 — Valid Accounts**:同一送信元からの 4625 の後に [4624](/ja/blog/understanding-event-id-4624) 成功 = 侵害。
- **T1556 — Modify Authentication Process**:異常な `LogonProcessName`（`User32`、`NtLmSsp`、`Kerberos`、`Advapi`、`Schannel` 以外）は認証スタック改ざんの兆候。

## 攻撃に見える誤検知

- **パスワード変更後に古くなった保存資格情報**。ユーザーのマップ ドライブ、スケジュールド タスク、サービス アカウントの設定が古いパスワードでリトライし続けます。パターン:1 つの `TargetUserName`、1 つの `IpAddress`（時には 1 つの `WorkstationName`）、安定した間隔の `0xC000006A`。古い資格情報を持つホストを探し、修正してください。
- **誤設定された自動化**:誤ったパスワードでループするスクリプト。形はブルートフォースと同じ。アラート前にオーナーに確認。
- **脆弱性スキャナ**は認証スキャン中に高密度の 4625 トラフィックを発生させます。スキャナ IP にタグを付けてください。
- **ロックアウト ポリシーの誤設定**:ヘルプデスクが過剰に解除する手順では、4625 → 4740 → 4624 のサイクルが繰り返し発生し得ます。

## 4625 では見えないもの

ドメイン コントローラからの NTLMv2 や Kerberos の失敗は、必ずしも有用な `IpAddress` を含みません — フィールドが空や `-` のことがあります。それらについては対応する DC イベント（Kerberos の事前認証失敗なら [4768](/ja/blog/event-id-4768-kerberos-tgt)/4771）またはネットワーク レベルのデータが必要です。「送信元 IP がないから調査しない」とは結論しないでください — DC チャネルへピボットしましょう。

`LogonProcessName` と `AuthenticationPackageName` フィールドは試行を処理した認証スタックを示します。よく見るのは `NtLmSsp`（NTLM）、`Kerberos`、`Negotiate`（両者から選択）です。`User32` はローカル コンソール、`Schannel` は TLS ベースです。

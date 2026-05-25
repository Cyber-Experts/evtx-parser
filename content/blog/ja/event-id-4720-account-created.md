---
title: "Event ID 4720 を解読する:AD における不正アカウント作成の検知"
description: "4720 はユーザー アカウントが作成されるたびに発火 — ローカルでも AD でも。4722/4724/4732 と一緒に読めば、永続化や横展開用アカウントを数分で発見できる。"
date: "2026-05-24"
---

Event ID **4720** — 「ユーザー アカウントが作成されました」 — は、新しいユーザー アカウントがプロビジョニングされるたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に書き込まれます。ドメイン コントローラでは新しい AD ユーザーごとに発火し、ワークステーションやメンバ サーバでは新しいローカル アカウントごとに発火します。成熟した現場では、4720 のトラフィックは圧倒的に HR ドリブンで予測可能です。その予測可能性こそが有用な理由です。バックドア アカウントを作成する攻撃者は、正当なトラフィックがこれほど規則的だからこそ目立ちます。

これはプラットフォームが生成する最も安価な永続化検知レコードの 1 つです。

## どこで発火するか

- **ドメイン アカウント**:4720 は作成を処理した DC に着地。すべての DC にわたって収集。
- **ローカル アカウント**:4720 はアカウントが作成されたホストに着地。メンバ ワークステーションからこれを捕捉するには WEF またはホスト単位の収集が必要 — 多くの現場はワークステーション Security 転送をスキップし、このシグナルを完全に失います。

攻撃者がすでに侵害したサーバ上に*ローカル*アカウントを作成する（バックアップ クレデンシャルとして多い）と、4720 はそのサーバにしか存在しません。カバレッジが重要です。

## レコードの中身

```xml
<Data Name="TargetUserName">svc_backup2</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetSid">S-1-5-21-...-1175</Data>
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f48c</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="SamAccountName">svc_backup2</Data>
<Data Name="DisplayName">-</Data>
<Data Name="UserPrincipalName">svc_backup2@corp.local</Data>
<Data Name="HomeDirectory">-</Data>
<Data Name="HomePath">-</Data>
<Data Name="ScriptPath">-</Data>
<Data Name="ProfilePath">-</Data>
<Data Name="UserWorkstations">-</Data>
<Data Name="PasswordLastSet">2026-05-24T12:04:11Z</Data>
<Data Name="AccountExpires">never</Data>
<Data Name="PrimaryGroupId">513</Data>
<Data Name="UserAccountControl">0x10</Data>
<Data Name="UserParameters">-</Data>
<Data Name="SidHistory">-</Data>
<Data Name="LogonHours">all</Data>
```

調査を駆動するフィールド。

- **`TargetUserName`** — 新規アカウント。リテラル名が最初のトリアージ シグナル:`svc_*`、`backup*`、`admin2`、`test`、`guest2`、正当なアカウントに似た名前（`administrator`、`administr0r`）、短いランダム文字列はすべて要確認。
- **`SubjectUserName` / `SubjectLogonId`** — *誰が*作成したか。そのセッションを作成した [4624](/ja/blog/understanding-event-id-4624) へピボット。業務時間外のワークステーション上の `LocalSystem` からの 4720 は、本物のプロビジョニング ワークフローではありません。
- **`UserAccountControl`** — *初期*の UAC フラグ セット。`0x10`（例）は `NORMAL_ACCOUNT`。危険なフラグはそれ以降の 4738（アカウント変更）レコードに現れます。完全な UAC ビットマップは MS-SAMR に。
- **`PrimaryGroupId`** — 513（Domain Users）は通常、新規アカウントの 512（Domain Admins）は本物のプロビジョニング ワークフローでは絶対にない、絶叫レベルの異常です。
- **`SidHistory`** — *新規作成*アカウントの非空 `SidHistory` は移行ツールの強い兆候 — または間違った文脈では偽造認証アーティファクト。

## 4720 は単独では来ない

アカウント作成は単一イベントであることはほぼありません。最小シーケンス。

| イベント | 意味 | なぜ気にするか |
|---|---|---|
| **4720** | ユーザー アカウント作成 | 見出し。 |
| **4722** | ユーザー アカウント有効化 | ログオン可能に設定。4722 が欠けていれば、アカウントは存在するがまだログオンできない。 |
| **4724** | パスワード リセット（管理者主導） | 誰か — 作成者と同じとは限らない — がパスワードを設定/リセット。 |
| **4738** | ユーザー アカウント変更 | UAC フラグ、有効期限、グループ、属性変更。 |
| **4732** | セキュリティ有効ローカル グループへのメンバ追加 | ローカル グループが `Administrators` なら、これが特権付与。 |
| **4728** | セキュリティ有効グローバル グループへのメンバ追加 | グローバル グループが `Domain Admins` か `Enterprise Admins` なら昇格。 |
| **4756** | セキュリティ有効ユニバーサル グループへのメンバ追加 | `Schema Admins`、`Enterprise Admins`、カスタム委任。 |

バックドア アカウントが作成されてデフォルト特権で放置されることは稀です。完全な連鎖 — `4720 → 4722 → 4724 → 4738（UAC フラグ）→ 4732/4728（グループ追加）` — は数秒以内に完了し、それが実際の永続化イベントです。

## トリアージ パターン

1. **新規アカウント → 数分で管理者グループ**:4720 の後 1 時間以内に 4732/4728 が特権グループへ、その特権グループ追加が変更管理システムのチケットに先行していない。4720 の `TargetSid` を 4732/4728 の `MemberSid` と組み合わせ。
2. **業務時間外の作成**:業務時間外の 4720 で `SubjectUserName` が自動プロビジョニングを行うサービス アカウントではない。
3. **似た名前**:既存ユーザー テーブルに対する `Levenshtein(TargetUserName, real_admin_name) <= 2`。`administrato`、`administr0r`、`helpd3sk` — すべて実例。
4. **最近侵害されたアカウントによる作成**:4720 の `SubjectLogonId` が異常な IP からの 4624、または対象が通常使わないワークステーションからの LogonType 3 の 4624 に遡る。
5. **ワークステーション上の `LocalSystem` による作成**:ドメイン コントローラや既知のプロビジョニング サーバ以外で `SubjectUserSid = S-1-5-18` の 4720。ほぼ常に悪意。
6. **`PrimaryGroupId == 512`**:通常のプロビジョニングでは絶対にない。ハード アラート。

## サンプル Sigma ルール

```yaml
title: Suspicious User Account Creation
id: 6f1e2db8-9a1d-44a0-b9d2-2f3c52f3b8a9
status: stable
description: A user account was created with suspicious indicators (off-hours, lookalike name, or by LocalSystem on a workstation).
references:
  - https://attack.mitre.org/techniques/T1136/001/
  - https://attack.mitre.org/techniques/T1136/002/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
  filter_localsystem:
    SubjectUserSid: 'S-1-5-18'
  filter_business_hours:
    EventTime|hour: [9, 10, 11, 12, 13, 14, 15, 16, 17]
  condition: selection and (filter_localsystem or not filter_business_hours)
falsepositives:
  - Legitimate provisioning automation running as SYSTEM via SCCM/Intune
  - After-hours admin workflows in 24/7 ops
level: medium
tags:
  - attack.persistence
  - attack.t1136
```

高信頼バリアント:`TargetSid` をスコープに、1 時間以内の特権グループへの 4732/4728 と組み合わせる。

## サンプル KQL — 4720 + 特権付与

KQL（Sentinel）— 「新規アカウント → 管理者グループ」ピボット:

```kusto
let creates =
    SecurityEvent
    | where EventID == 4720
    | project CreateTime=TimeGenerated, NewUserSid=TargetSid, NewUser=TargetUserName,
              Creator=SubjectUserName, CreatorHost=Computer;
let privileged_groups = dynamic([
    "S-1-5-32-544",                            // Local Administrators
    "S-1-5-21-DOMAIN-512",                     // Domain Admins (replace -DOMAIN- with your domain SID)
    "S-1-5-21-DOMAIN-519"                      // Enterprise Admins
]);
SecurityEvent
| where EventID in (4732, 4728, 4756)
| where TargetSid in (privileged_groups)
| project AddTime=TimeGenerated, MemberSid, TargetSid, AdminHost=Computer
| join kind=inner (creates) on $left.MemberSid == $right.NewUserSid
| where AddTime between (CreateTime .. CreateTime + 1h)
| project CreateTime, NewUser, Creator, CreatorHost, AdminHost, AddTime, AddedToGroup=TargetSid
| order by CreateTime desc
```

## サンプル Splunk

```spl
index=wineventlog EventCode=4720
| join TargetSid type=inner
    [ search index=wineventlog (EventCode=4732 OR EventCode=4728 OR EventCode=4756)
      (TargetSid="S-1-5-32-544" OR TargetSid="*-512" OR TargetSid="*-519")
    | rename MemberSid AS TargetSid, _time AS add_time
    | fields TargetSid add_time TargetSid_Group=TargetSid ]
| where add_time - _time < 3600
| table _time TargetUserName SubjectUserName Computer add_time TargetSid_Group
```

## ATT&CK マッピング

- **T1136.001 — Create Account: Local Account**:ワークステーション / サーバのローカル アカウント。
- **T1136.002 — Create Account: Domain Account**:DC で記録される作成。
- **T1136.003 — Create Account: Cloud Account** — 4720 を発火させ*ません*（クラウド アカウント作成は Windows Security ではなく Azure AD 監査ログ / 統合監査ログに記録）。
- **T1098 — Account Manipulation**:4720 の後にグループ昇格や属性変更が続くケース。

## 攻撃そっくりの誤検知

- **一括移行ツール**（ADMT、Quest Migration Manager）は `SidHistory` 付きでアカウントを高速作成。トラフィックの形は高速攻撃者と同一。既知の移行ウィンドウをベースライン化。
- **入社者パイプライン**(HR ドリブンのプロビジョニング ワークフロー）は予測可能な時刻に 4720 を発火。業務時間外の 4720 すべてにアラートを出すと、深夜過ぎまで流れる HR システム実行で埋もれます。
- **SCCM / Intune / Jamf スタイル**の管理ツールは OS プロビジョニング用にローカル アカウントを作成。`SubjectUserSid` は既知のビルド ホスト上で `S-1-5-18`（LocalSystem）。それらのホストにタグ。
- **サービス インストーラ**の中には初回実行時にローカル サービス アカウントを作成する古い製品があります。インストーラをベースライン化。

堅実な 4720 検知は、作成と必ずフォローアップ シグナル（グループ追加、既知の弱いパターンへのパスワード変更、異常ホストからの即時ログイン）を組み合わせます。スタンドアロンの作成はノイズが多すぎます。

## 4720 では分からないこと

レコードには新規アカウントの*パスワード*は含まれません（Windows はどこにも一切記録しません）。また、*対象ドメイン*の SID は明示的に含まれません。ドメインは `TargetDomainName` から読むか、`TargetSid` のドメイン部分から導出します。

メンバ ワークステーションでのローカル アカウント作成は DC からは見えません。ワークステーションから Security を収集していなければ（多くの現場が収集していない）、すべてのローカル バックドア アカウントを取りこぼします。Sysmon と本物の EDR がギャップの一部を埋めますが（ローカル SAM が触れられた時のファイル作成 / レジストリ変更パターン）、4720 の転送が最も安価です。

## タイムラインにおける 4720 の位置

教科書的な永続化連鎖。

1. [**4624**](/ja/blog/understanding-event-id-4624) — フィッシングされたユーザーによる初期ドメイン ログオン。
2. [**4769**](/ja/blog/event-id-4769-kerberoasting) バースト — ドメイン サービス アカウントへのケルベロースト。
3. メンバ サーバ上、侵害されたサービス アカウントとしての **4624**。
4. [**4688**](/ja/blog/event-id-4688-process-creation) — `net user svc_backup2 P@ssw0rd! /add /domain`（または PowerShell `New-ADUser` で同等）。
5. **4720** — DC 上でアカウント作成。
6. **4724** — パスワード設定。
7. **4722** — アカウント有効化。
8. **4728** — Domain Admins に追加。
9. [**7045**](/ja/blog/service-creation-event-id-7045) — 新アカウント下でサーバにサービス インストール。

4720 単独で計測すれば、ステップ 5 で永続化を捕捉できます — ステップ 6〜9 がダメージを与える前に。これが価値です。

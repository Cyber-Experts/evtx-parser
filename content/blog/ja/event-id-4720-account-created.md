---
title: "Event ID 4720 を解説: AD 内の不正アカウント作成を検出する"
description: "4720 はローカル/ドメインを問わず、ユーザー アカウントが作成されるたびに発火します。4722、4724、4732 と一緒に読めば、永続化アカウントと横方向移動アカウントを数分で捕まえられます。"
date: "2026-05-24"
---

Event ID **4720**「ユーザー アカウントが作成されました」は、新しいユーザーがプロビジョニングされるたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に届きます。ドメイン コントローラー上では、新しい AD ユーザーごとに発火します。ワークステーションやメンバー サーバー上では、新しいローカル アカウントごとに発火します。成熟したショップでは、4720 トラフィックは圧倒的に HR 駆動で予測可能です。その予測可能性が、これを有用にします。攻撃者がバックドア アカウントを作ると、正当なトラフィックがそれだけ規則正しいために際立ちます。

これはプラットフォームが生成する最も安価な永続化検知レコードの 1 つです。これだけでケースを閉じたことがあります。

## どこで発火するか

- ドメイン アカウント: 作成を処理した DC 上で 4720 が届きます。すべての DC で収集してください。
- ローカル アカウント: アカウントが作成されたホスト上で 4720 が届きます。メンバー ワークステーションからこれを捕えるには WEF またはホスト単位の収集が必要です。多くのショップはワークステーション Security 転送をスキップし、このシグナルを完全に失っています。

攻撃者が既に侵害したサーバー上に*ローカル*アカウントを作る場合 (バックアップ資格情報として多い)、4720 はそのサーバーにしかありません。カバレッジがルールよりも重要です。

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

調査を駆動するフィールド:

- `TargetUserName`。新しいアカウント。文字どおりの名前が最初のトリアージ シグナルです。`svc_*`、`backup*`、`admin2`、`test`、`guest2`、正当なアカウントに似せたもの (`administrator`、`administr0r`)、短いランダム文字列はすべて、もっとよく見る価値があります。
- `SubjectUserName` と `SubjectLogonId`。誰が作成したか。そのセッションを作成した [4624](/ja/blog/understanding-event-id-4624) に軸を変えてください。営業時間外のワークステーション上の `LocalSystem` からの 4720 は、実際のプロビジョニング ワークフローではありません。
- `UserAccountControl`。UAC フラグの*初期*セット。例の `0x10` は `NORMAL_ACCOUNT` です。危険なフラグは後続の 4738 レコードに現れます。
- `PrimaryGroupId`。513 (Domain Users) は通常。新しいアカウントの 512 (Domain Admins) は声高に叫ぶ存在で、実際のプロビジョニング ワークフローでは決して起きてはなりません。
- `SidHistory`。新規作成アカウントで空でないのは、移行ツールか、文脈が悪ければ偽造された認証アーティファクトです。

## 4720 は単独では来ない

アカウント作成が単一イベントであることはほぼありません。最小シーケンス:

| Event | 意味 | なぜ重要か |
|---|---|---|
| **4720** | ユーザー アカウント作成 | 見出し。 |
| **4722** | ユーザー アカウント有効化 | アカウントがログオン可能に設定された。4722 がなければ、アカウントは存在するがまだログオンできない。 |
| **4724** | パスワード リセット (管理者主導) | 誰か、作成者でないかもしれない、がパスワードを設定またはリセットした。 |
| **4738** | ユーザー アカウント変更 | UAC フラグ、有効期限、グループ、属性変更。 |
| **4732** | セキュリティ有効のローカル グループにメンバー追加 | ローカル グループが `Administrators` なら、これが特権付与。 |
| **4728** | セキュリティ有効のグローバル グループにメンバー追加 | グローバル グループが `Domain Admins` や `Enterprise Admins` なら、昇格。 |
| **4756** | セキュリティ有効のユニバーサル グループにメンバー追加 | `Schema Admins`、`Enterprise Admins`、カスタム委任。 |

バックドア アカウントが作成されてデフォルト特権のまま放置されることはまずありません。完全なチェーン (4720、4722、4724、4738、4732/4728) は数秒で完了し、実際の永続化イベントです。

## トリアージ パターン

1. **数分以内に管理者グループに入る新規アカウント**。1 時間以内に 4732 または 4728 で特権グループに追加され、その特権グループ追加がチケットに先行されていない 4720。4720 の `TargetSid` を 4732/4728 の `MemberSid` と組み合わせ。
2. **業務時間外作成**。自動プロビジョニングを実行するサービス アカウントでない `SubjectUserName` による業務時間外の 4720。
3. **似せた名前**。既存ユーザー テーブルに対する `Levenshtein(TargetUserName, real_admin_name) <= 2`。`administrato`、`administr0r`、`helpd3sk`。すべて実在。
4. **最近侵害されたアカウントによる作成**。`SubjectLogonId` が異常な IP からの 4624、または対象が通常使わないワークステーションからの LogonType 3 の 4624 に遡る 4720。
5. **ワークステーション上の LocalSystem による作成**。ドメイン コントローラーや既知のプロビジョニング サーバー以外で `SubjectUserSid = S-1-5-18` を持つ 4720。ほぼ常に悪意あり。
6. **PrimaryGroupId == 512**。通常のプロビジョニングでは決して起きません。ハード アラート。

## Sigma

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

高信頼度のバリアントは、4720 を 1 時間以内の特権グループへの 4732 または 4728 と組み合わせ、`TargetSid` でスコープします。

## KQL: 4720 と特権付与

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

## Splunk

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

- T1136.001 Create Account: Local Account。ワークステーションとサーバーのローカル アカウント。
- T1136.002 Create Account: Domain Account。DC 記録の作成。
- T1136.003 Create Account: Cloud Account。4720 を*発火しません*。クラウド作成は Entra ID 監査ログ / 統合監査ログに住んでいます。
- T1098 Account Manipulation。4720 がグループ昇格や属性変更を伴うとき。

## 攻撃に見える誤検知

- 一括移行ツール (ADMT、Quest Migration Manager) は、`SidHistory` を設定して高速にアカウントを作成します。形は高速な攻撃者と同一です。既知の移行ウィンドウをベースライン化。
- HR 駆動プロビジョニング ワークフローの Joiner パイプラインは、予測可能な時刻に 4720 を発火します。すべての業務時間外 4720 にアラートすると、深夜にまたがる HR 実行に埋もれます。
- SCCM、Intune、Jamf スタイルの管理ツールは OS プロビジョニングのためにローカル アカウントを作成します。`SubjectUserSid` は既知のビルド ホスト上で `S-1-5-18`。それらにタグを。
- 一部のレガシー製品のサービス インストーラーは、初回起動時にローカル サービス アカウントを作成します。インストーラーをベースライン化。

しっかりした 4720 検知は常に作成をフォロー アップ シグナル (グループ追加、既知の弱パターンへのパスワード変更、異常ホストからの即時ログイン) と組み合わせます。スタンドアロンの作成はノイズが多すぎます。

## 4720 が教えないこと

レコードには新アカウントのパスワードは含まれません (Windows はそれをどこにも記録しません)。また、対象ドメインの SID を明示的には含みません。ドメインは `TargetDomainName` から読むか、`TargetSid` のドメイン部分から導出します。

メンバー ワークステーション上のローカル アカウント作成は DC からは見えません。ワークステーションから Security を収集していなければ (ほとんどのショップが収集していません)、すべてのローカル バックドア アカウントを取りこぼします。Sysmon と本格的な EDR はギャップの一部を埋めます (ローカル SAM が触られたときのファイル作成とレジストリ変更パターン) が、4720 転送は最も安価な制御です。ログ転送が off だったときの裏付けは [registry](https://www.registryparser.com) ハイブ スナップショットです。

## タイムラインでの 4720 の位置

教科書的な永続化チェーン:

1. [4624](/ja/blog/understanding-event-id-4624)。フィッシングを受けたユーザーによる初期ドメイン ログオン。
2. [4769](/ja/blog/event-id-4769-kerberoasting) バースト。ドメイン サービス アカウントに対する Kerberoasting。
3. メンバー サーバー上の侵害されたサービス アカウントとしての 4624。
4. [4688](/ja/blog/event-id-4688-process-creation)。`net user svc_backup2 P@ssw0rd! /add /domain` (または PowerShell 経由の `New-ADUser`)。
5. **4720**。DC でアカウント作成。
6. 4724。パスワード設定。
7. 4722。アカウント有効化。
8. 4728。Domain Admins に追加。
9. [7045](/ja/blog/service-creation-event-id-7045)。新アカウントで動作するサーバー上のサービス インストール。

4720 単独を計装すれば、ステップ 5 で永続化を捕え、ステップ 6 〜 9 がダメージを与える前に対応できます。それが価値です。

## 参考資料

- [4720 の Microsoft ドキュメント](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)

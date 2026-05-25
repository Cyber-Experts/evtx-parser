---
title: "Event ID 4672 を解読する:Windows での特権ログオン検知"
description: "4672 は、SeDebugPrivilege や SeTcbPrivilege のような重要な特権がログオンに付与されるたびに発火。「このログオンは管理者相当」というシグナルとして読めば、監査ポリシーの残りが腑に落ちる。"
date: "2026-05-24"
---

Event ID **4672** — 「新しいログオンに特権が割り当てられました」 — は、ログオン セッションが Windows の重要な特権のうち固定セットの 1 つを付与されるたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に記録されます。実用上これが意味するのは:管理者相当のログオンが成功するたびに、対応する [4624](/ja/blog/understanding-event-id-4624) の直後に 4672 が生成されるということです。ほとんどのワークステーションでは 4672 は稀ですが、ドメイン コントローラと管理 ジャンプボックスでは常時発生します。その非対称性こそが有用な理由です。

Security レコードを 1 つのフィールドだけでフィルタするなら、「過去 1 週間のすべての 4672」が、「組織内のすべての特権セッションを見せて」を実現する最も安価なクエリです。

## どこで発火するか

[4624](/ja/blog/understanding-event-id-4624) と同じく、ログオンが実際に起きたホスト上で常に発火します。`SERVER01` へのネットワーク ログオンは、4624 と（特権付きなら）4672 を `SERVER01` 上に生成し、元のワークステーションには生成しません。スケールで 4672 から何かを検知するには、最低でもサーバと DC からの Security 収集が必要で、ボリュームを負担できるなら管理ワークステーションとジャンプホストからも必要です。

## レコードの中身

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1a3c5</Data>
<Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege
  SeTcbPrivilege
  SeSecurityPrivilege
  SeTakeOwnershipPrivilege
  SeLoadDriverPrivilege
  SeBackupPrivilege
  SeRestorePrivilege
  SeDebugPrivilege
  SeSystemEnvironmentPrivilege
  SeImpersonatePrivilege</Data>
```

各フィールド。

- **`SubjectLogonId`** — 対応する [4624](/ja/blog/understanding-event-id-4624) に現れる同じ `LogonId`。これがピボット軸です。すべての 4672 は、正確に 1 つの 4624（およびそのセッション内の以降のすべてのレコード）と、そのログオンが得た特権セットを結びつけます。
- **`PrivilegeList`** — 実際の特権セット。Windows はここに「重要」特権の固定セットのみ（監査ポリシーで定義）を記録します。ログオンはレコードが示すよりも多くの特権を保持している場合があります。省略されたもの — `SeLockMemoryPrivilege`、`SeIncreaseBasePriorityPrivilege` など — はセキュリティ上の重要性がなく、意図的にこのレコードから刈り取られています。
- **`Subject*`** — ログオンの所属者。ほぼ常に対応する 4624 の同フィールドと同一。

4672 自体には `IpAddress`、`LogonType`、`WorkstationName` がありません。それらを得るには `SubjectLogonId` で 4624 に join します。

## 特権とその意味

| 特権 | 表示名 | なぜ重要か |
|---|---|---|
| `SeDebugPrivilege` | プログラムのデバッグ | 任意のプロセスのメモリを読み書き — `lsass.exe` を含む。Mimikatz が必要とする。 |
| `SeTcbPrivilege` | オペレーティング システムの一部として機能 | 実質 `LocalSystem`。LocalSystem 自身にのみ現れるべき。 |
| `SeImpersonatePrivilege` | 認証後にクライアントを偽装 | `SeImpersonatePrivilege` 悪用ファミリ（PrintSpoofer、JuicyPotato、RoguePotato）が使う特権。 |
| `SeAssignPrimaryTokenPrivilege` | プロセス レベル トークンの置換 | トークン偽装ツール。 |
| `SeBackupPrivilege` / `SeRestorePrivilege` | ファイルのバックアップ / 復元 | ACL をバイパスして任意ファイルを読み書き — レジストリ ハイブを含む。`reg save HKLM\SAM` がこれらで動く。 |
| `SeTakeOwnershipPrivilege` | ファイルの所有権取得 | ファイル ACL を上書き。 |
| `SeLoadDriverPrivilege` | デバイス ドライバのロード / アンロード | BYOVD（bring-your-own-vulnerable-driver）攻撃に必須。 |
| `SeSecurityPrivilege` | 監査とセキュリティ ログの管理 | Security イベント ログの読み取り / クリア。[1102](/ja/blog/event-id-1102-cleared-log) を発火させるのに必要。 |
| `SeSystemEnvironmentPrivilege` | ファームウェア環境値の変更 | ブートキット、EFI 改ざん。 |
| `SeChangeNotifyPrivilege` | トラバース チェックのバイパス | ほとんどのログオンで一般的。トリアージ シグナルにはならない。 |

これらの一部はあらゆる管理者ログオンで期待されます（`SeDebugPrivilege`、`SeBackupPrivilege`）。他はより稀であるべき（`SeLoadDriverPrivilege`、`SeTcbPrivilege`）。シグナルは*間違ったアカウント*に*想定外の特権*が現れることにあります。

## トリアージ パターン

### 1. 誰が 4672 を出すかをベースライン化

健全な環境では、4672 の生成者は*小さく既知の*セットです。

- `LocalSystem`（S-1-5-18） — すべてのホスト、常時、サービス起動時に。
- `NetworkService`（S-1-5-20） — 偽装可能なサービスを動かすサーバで一般的。
- 名前ではなく SID で識別される一握りの管理者。

それ以外で 4672 を生成するのは、あなたが知らなかった新しい管理者、特権昇格イベント、誤設定アカウントのいずれかです。

最も安価なベースライン クエリ:過去 30 日の 4672 から distinct な `SubjectUserSid` を頻度順にソート。上位 N 生成者の外側にあるものは確認価値あり。

### 2. 非特権アカウントの SeImpersonatePrivilege

4672 が管理者でも `*Service` SID でもないアカウントに `SeImpersonatePrivilege` を示したら、ほぼ確実に「Potato」ファミリのエスカレーション（PrintSpoofer、JuicyPotato、RoguePotato、GodPotato）です。これらの悪用は `IIS_IUSRS` やサービス トークン呼び出し元に `SYSTEM` を与えます。4672 は*特権が取得されたとき*に発火します — 新しい特権でスポーンされたプロセスがどれか可視化されるよりも早いです。

### 3. 管理者グループに属さない SeDebugPrivilege

`SeDebugPrivilege` はポリシーによりローカル管理者に付与されます。非管理者アカウントで見えるのは、ポリシーが変更された（通常 LSASS アクセスを可能にするため攻撃者によって）か、攻撃者が管理者プロセスにインジェクションしたサインです。

### 4. 業務時間外の特権ログオン

日曜午前 3 時の実在管理者アカウントによる 4672 は、最も安価な「業務時間外管理者活動」アラートです。対応する 4624 の `LogonType` と `IpAddress` を組み合わせて文脈を得てください。

### 5. サービス アカウントのドリフト

歴史的に `SeImpersonatePrivilege` と `SeAssignPrimaryTokenPrivilege` だけを発火させていたサービス アカウントが、突然 `SeBackupPrivilege` と `SeDebugPrivilege` を含む 4672 を出すなら、誰かがグループ メンバシップを変更しました。メンバシップ変更を見つけるため 4732/4728 と組み合わせてください。

## サンプル Sigma ルール — 非管理者への SeDebugPrivilege

```yaml
title: SeDebugPrivilege Granted to Non-Admin Account
id: 8a3b1d20-77e1-4a4c-8a3b-1e8f2c1b9a0f
status: stable
description: Event 4672 grants SeDebugPrivilege to an account that should not have administrative rights.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/techniques/T1134/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
    PrivilegeList|contains: 'SeDebugPrivilege'
  filter_known_service_sids:
    SubjectUserSid:
      - 'S-1-5-18'  # LocalSystem
      - 'S-1-5-19'  # LocalService
      - 'S-1-5-20'  # NetworkService
  filter_known_admins:
    SubjectUserName|endswith:
      - '_adm'
      - '-admin'
      - 'admin'
  condition: selection and not (filter_known_service_sids or filter_known_admins)
falsepositives:
  - Legitimate administrators not matching the naming pattern
  - Forensic / debugging tools running under non-admin accounts in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

`filter_known_admins` は環境ごとにチューニング。命名パターンではなく SID リストを使う現場もあります。

## サンプル KQL — Potato ファミリ エスカレーション

```kusto
SecurityEvent
| where EventID == 4672
| where PrivilegeList contains "SeImpersonatePrivilege"
| where SubjectUserSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where AccountName !in ("LocalSystem", "NetworkService", "LocalService")
    | project LogonTime=TimeGenerated, SubjectLogonId=TargetLogonId,
              LogonType, IpAddress, AccountName
) on SubjectLogonId
| project TimeGenerated, AccountName, LogonType, IpAddress, PrivilegeList, Computer
| order by TimeGenerated desc
```

## サンプル Splunk — 管理者ログオン ベースライン

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

毎週実行。異常は上位 50 に新規アカウントとして現れます。

## ATT&CK マッピング

- **T1134.001 — Access Token Manipulation: Token Impersonation/Theft**:非特権アカウントへの SeImpersonatePrivilege。
- **T1003.001 — OS Credential Dumping: LSASS Memory**:SeDebugPrivilege が前提条件。
- **T1068 — Exploitation for Privilege Escalation**:あらゆる想定外の特権獲得。
- **T1078 — Valid Accounts**:通常と異なる送信元からの正当な管理者アカウントの 4672。
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**:`ClearEventLog` を呼ぶには SeSecurityPrivilege が必要。この特権を持つ 4672 の直後の [1102](/ja/blog/event-id-1102-cleared-log) はパンくずの跡。

## 攻撃そっくりの誤検知

- **バックアップ ソフトウェア**（Veeam、Commvault）は、サービス アカウントから `SeBackupPrivilege` + `SeRestorePrivilege` で日常的に 4672 を発火させます。サービス アカウント SID でベースライン化。
- **監視エージェント**（SCOM、カスタム WMI コレクタ）でセキュリティ関連データを読むものは、4672 を広範に発火させます。エージェント ホストにタグ付け。
- **一部のログオン スクリプト**ランナーが特権コンテキスト下で動くと、ログオン時に 4672 の連鎖を生成します。
- **Hyper-V / VMM / コンテナ ホスト**は `LocalSystem` と管理サービス アカウントから高密度の 4672 トラフィックを生成します。

シグナルは*新規の*生成者にあり、*繰り返しの*生成者ではありません。過去 1 年毎日発火していた 4672 生成者は設定です。今週初めて現れたものが手がかりです。

## 4672 では分からないこと

- **プロセス情報なし**:特権付与は見えますが、特権プロセスが何をしたかは見えません。前向きに追うには、`SubjectLogonId` を同じセッションの [4688](/ja/blog/event-id-4688-process-creation) / [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) レコードにピボット。
- **送信元 IP は直接含まれない**:[4624](/ja/blog/understanding-event-id-4624) に `SubjectLogonId` で join して取得。
- **すべての特権アクションではない**:*ログオン時の付与*のみ記録。以降の使用（例:`RtlAdjustPrivilege` による `SeDebugPrivilege` の on/off）は 4673/4674 を生成し、別の 4672 ではありません。
- **Special Logon 監査がオフだと取りこぼし**:監査サブカテゴリは *Audit Special Logon* で、success イベントを有効にする必要があります。最新の Windows ではデフォルト オンですが、検証する価値はあります。

## タイムラインにおける 4672 の位置

教科書的なエスカレーション & クリーンアップ連鎖。

1. [**4624**](/ja/blog/understanding-event-id-4624) — 攻撃者制御 IP からの LogonType 3、低特権ユーザー。
2. *(静か)* — `SeImpersonatePrivilege` ベースのエスカレーション（PrintSpoofer など）。
3. **4672** — `LocalSystem` として動く新しいログオン セッションに `SeImpersonatePrivilege` + `SeTcbPrivilege` 付与。**ここでエスカレーションが可視化。**
4. [**4688**](/ja/blog/event-id-4688-process-creation) — 偽装トークン経由で SYSTEM として動く `cmd.exe` または `powershell.exe`。
5. [**4104**](/ja/blog/powershell-4104-scriptblock) — LSASS に対する `Invoke-Mimikatz` または `comsvcs.dll MiniDump` — SeDebugPrivilege がこれを成立させる。
6. [**1102**](/ja/blog/event-id-1102-cleared-log) — Security ログのクリア。ステップ 3 の SeSecurityPrivilege でこれが可能。
7. **4672** — LSASS メモリから抽出したドメイン管理者としての 2 つ目の特権セッション。

ステップ 3 と 7 の 4672 が連鎖中で最も安価な検知点です。これらがなければ、プロセス イベントだけから偽装を組み立てる必要があり — 遅く、見逃しやすくなります。

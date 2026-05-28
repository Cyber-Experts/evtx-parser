---
title: "Event ID 4672 を解説: Windows での特権ログオン検出"
description: "4672 は、SeDebugPrivilege や SeTcbPrivilege のようなセンシティブな特権がログオンに与えられたときに発火します。「このログオンは管理者相当」のシグナルとして読めば、監査ポリシーの残りが整います。"
date: "2026-05-24"
---

Event ID **4672**「新しいログオンに特殊な特権が割り当てられました」は、ログオン セッションが固定セットのセンシティブな Windows 特権の 1 つを付与されるたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に発火します。実務上、成功した管理者相当のログオンはすべて、対応する [4624](/ja/blog/understanding-event-id-4624) の直後に書かれる 4672 を生成します。多くのワークステーションで 4672 は稀です。ドメイン コントローラーや管理者ジャンプホストでは常時起きています。その非対称性が、これを有用にします。

今週 Security を 1 つのフィールドだけでフィルタするなら、「過去 7 日間のすべての 4672」を走らせてください。書ける限り最も安価な「この資産にあるすべての特権セッションを見せて」クエリです。

## どこで発火するか

[4624](/ja/blog/understanding-event-id-4624) と同様、実際にログオンが起きたホスト上です。`SERVER01` へのネットワーク ログオンは、発信元ワークステーションではなく `SERVER01` 上で 4624 と 4672 を生成します。スケールで 4672 から何かを検出するには、少なくともサーバーと DC からの Security 収集が必要です。ボリュームを許せる限り、管理者ワークステーションとジャンプホストも。

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

フィールド:

- `SubjectLogonId`。対応する [4624](/ja/blog/understanding-event-id-4624) と同じ `LogonId`。これがあなたの軸です。すべての 4672 は、ちょうど 1 つの 4624 (とそのセッション内のすべての後続レコード) を、ログオンが得た特権セットに結びつけます。
- `PrivilegeList`。実際の特権バッグ。Windows は監査ポリシーで定義された「センシティブ」な特権だけをログに記録します。ログオンはレコードに表れる以上の特権を保持しているかもしれません。省略されたもの (`SeLockMemoryPrivilege`、`SeIncreaseBasePriorityPrivilege` 等) はセキュリティ非関連で、意図的にこのレコードから取り除かれます。
- `Subject*`。ログオンの所有者。対応する 4624 とほぼ同一です。

4672 自体には `IpAddress`、`LogonType`、`WorkstationName` はありません。それらを得るには、`SubjectLogonId` 経由で 4624 にジョインします。4672 単独でアラートしようとするアナリストは、これを見落としてエンリッチできないレコードを抱えがちです。

## 特権とその意味

| 特権 | 表示名 | 重要な理由 |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | `lsass.exe` を含む任意のプロセスのメモリを読み書き。Mimikatz が必要とします。 |
| `SeTcbPrivilege` | Act as part of the OS | 事実上 `LocalSystem`。LocalSystem のためだけに現れるべき。 |
| `SeImpersonatePrivilege` | Impersonate a client after auth | Potato ファミリ (PrintSpoofer、JuicyPotato、RoguePotato、GodPotato) が使う特権。 |
| `SeAssignPrimaryTokenPrivilege` | Replace a process token | トークン偽装ツール。 |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore | レジストリ ハイブを含む任意のファイルを読み書きするため ACL をバイパス。`reg save HKLM\SAM` はこれで動きます。 |
| `SeTakeOwnershipPrivilege` | Take ownership | ファイル ACL を上書き。 |
| `SeLoadDriverPrivilege` | Load drivers | BYOVD (bring-your-own-vulnerable-driver) に必要。 |
| `SeSecurityPrivilege` | Manage audit log | Security を読むまたはクリアする。[1102](/ja/blog/event-id-1102-cleared-log) を発火させるために必要。 |
| `SeSystemEnvironmentPrivilege` | Modify firmware | ブートキット、EFI 改ざん。 |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | ほとんどのログオンで一般的。トリアージ シグナルではない。 |

すべての管理者ログオンで期待される特権もあります (`SeDebugPrivilege`、`SeBackupPrivilege`)。より稀であるべきものもあります (`SeLoadDriverPrivilege`、`SeTcbPrivilege`)。シグナルは*間違ったアカウント*に対する*予期しない*特権です。

## パターン

### 誰が 4672 を出すかのベースライン

健全な資産では、4672 の発生源は小さな既知のセットです:

- `LocalSystem` (S-1-5-18)。すべてのホストで、すべての時間、サービス起動時に。
- `NetworkService` (S-1-5-20)。偽装可能なサービスを動かしているサーバーで一般的。
- 名前ではなく SID で識別される、ひと握りの管理者。

それ以外は、知らなかった新しい管理者、特権昇格イベント、または構成ミスのアカウントです。

最も安価なベースライン クエリ: 過去 30 日間の 4672 からの distinct `SubjectUserSid`、頻度ソート。トップ N の外は一見の価値ありです。

### 非特権アカウントへの SeImpersonatePrivilege

管理者でも `*Service` SID でもないアカウントで `SeImpersonatePrivilege` を示す 4672 が出たら、ほぼ確実に Potato 系の昇格です。これらのエクスプロイトは `IIS_IUSRS` またはサービス トークン呼び出し元に `SYSTEM` を与えます。4672 は*特権が取得される時*に発火します。これは新しい特権でスポーンされる可視プロセスより早いです。

### 管理者グループなしでの SeDebugPrivilege

`SeDebugPrivilege` はポリシーによりローカル管理者に付与されます。非管理者アカウントでは、ポリシーが変更された (通常は攻撃者が LSASS アクセスを有効化するため) か、攻撃者が管理者プロセスに注入したかのどちらかです。

### 業務時間外の特権ログオン

日曜の午前 3 時の実管理者アカウントに対する 4672 は、存在する中で最も安価な時間外アラートです。コンテキストには、対応する 4624 の `LogonType` と `IpAddress` を組み合わせてください。

### サービス アカウントのドリフト

歴史的に `SeImpersonatePrivilege` と `SeAssignPrimaryTokenPrivilege` しか発火しないサービス アカウントが、突然 `SeBackupPrivilege` と `SeDebugPrivilege` を持つ 4672 を生成し始めたら、誰かがそのグループ メンバーシップを変更したことを意味します。メンバーシップ変更を見つけるため 4732 または 4728 と組み合わせてください。

## Sigma: 非管理者への SeDebugPrivilege

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
  - Forensic / debugging tools in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

`filter_known_admins` を環境ごとに調整してください。ショップによっては名前パターンではなく SID リストを使います。

## KQL: Potato ファミリの昇格

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

## Splunk: 管理者ログオン ベースライン

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

これを毎週実行してください。トップ 50 に現れる新しいアカウントが異常です。

## ATT&CK マッピング

- T1134.001 Token Impersonation/Theft。非特権アカウントの SeImpersonatePrivilege。
- T1003.001 LSASS Memory。SeDebugPrivilege が前提。
- T1068 Exploitation for Privilege Escalation。予期しない特権獲得。
- T1078 Valid Accounts。異常なソースからの正当な管理者アカウントの 4672。
- T1562.002 Disable Windows Event Logging。`ClearEventLog` 呼び出しには SeSecurityPrivilege が必要。[1102](/ja/blog/event-id-1102-cleared-log) の直前にこの特権を運ぶ 4672 は、パンくずです。

## 攻撃に見える誤検知

- バックアップ ソフトウェア (Veeam、Commvault) は、サービス アカウントから `SeBackupPrivilege` + `SeRestorePrivilege` を持つ 4672 を日常的に発火します。サービス アカウント SID でベースライン化。
- 監視エージェント (SCOM、カスタム WMI コレクター) は 4672 を広く誘発します。エージェント ホストにタグ。
- 特権コンテキスト下のログオン スクリプト ランナーは、ログオン時に 4672 チェーンを生成します。
- Hyper-V、VMM、コンテナ ホストは、`LocalSystem` とマネージド サービス アカウントから密な 4672 を生成します。

シグナルは*新しい*生成源で、*繰り返している*ものではありません。過去 1 年間毎日発火している 4672 生成源は構成です。今週初めて現れたものがリードです。

## 4672 が教えないこと

- プロセス情報なし。特権付与は見えますが、特権プロセスが何をしたかは見えません。前方に追うには、同じセッション内の [4688](/ja/blog/event-id-4688-process-creation) または [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) レコードに `SubjectLogonId` で軸を変えてください。
- 直接の送信元 IP なし。`SubjectLogonId` 経由で [4624](/ja/blog/understanding-event-id-4624) にジョインします。
- すべての特権アクションではない。*ログオン時の付与*のみが記録されます。後続の使用 (例: `SeDebugPrivilege` を on/off する `RtlAdjustPrivilege`) は別の 4672 ではなく 4673/4674 レコードを生成します。
- Special Logon 監査がオフだと見逃します。監査サブポリシーは *Audit Special Logon* です。最新の Windows では既定でオン、ただし検証する価値あり。

## タイムラインでの 4672 の位置

教科書的な昇格とクリーンアップのチェーン:

1. [4624](/ja/blog/understanding-event-id-4624)。攻撃者制御の IP からの LogonType 3、低特権ユーザー。
2. *(沈黙)*。SeImpersonatePrivilege ベースの昇格 (PrintSpoofer など)。
3. **4672**。LocalSystem として動作する新規ログオン セッションに SeImpersonatePrivilege + SeTcbPrivilege が付与。ここで昇格が見えます。
4. [4688](/ja/blog/event-id-4688-process-creation)。偽装トークン経由の SYSTEM としての `cmd.exe` または `powershell.exe`。
5. [4104](/ja/blog/powershell-4104-scriptblock)。LSASS に対する `Invoke-Mimikatz` または `comsvcs.dll MiniDump`。これを可能にするのが SeDebugPrivilege。
6. [1102](/ja/blog/event-id-1102-cleared-log)。Security ログ クリア。ステップ 3 からの SeSecurityPrivilege がこれを可能にしました。
7. **4672**。LSASS メモリから抽出されたドメイン管理者としての 2 つ目の特権セッション。

ステップ 3 と 7 の 4672 は、最も安価な検知点です。それなしには、プロセス イベントだけから偽装を組み立てることになり、より遅く、見落としやすくなります。

## 参考資料

- [4672 の Microsoft ドキュメント](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [SpecterOps: An Introduction to Manipulating Token Privileges](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)

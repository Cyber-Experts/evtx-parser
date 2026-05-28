---
title: "Event ID 4663 を解説: SACL によるファイルとレジストリのアクセス監査"
description: "4663 はアクセスごとに発生するオブジェクト監査レコードです。適切なファイルとキーに SACL を設定すれば、誰が何に触れたかを 1 バイト単位で記録できます。ランサムウェア、エクスフィル、資格情報ストア窃取に有用です。"
date: "2026-05-24"
---

Event ID **4663**「オブジェクトへのアクセスが試行されました」は、監査対象のファイル、レジストリ キー、またはカーネル オブジェクトが SACL (System Access Control List) と一致する方法で触れられるたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に発火します。多くの Security レコードと異なり、4663 は既定では何も生成しません。オブジェクトの SACL を*設定*する必要があります。これがほとんどの環境にない理由です。同時に、設定している環境が、わずかなテクニックに対して反則レベルの検知優位を持つ理由でもあります。

4663 をちょうど 5 つのものに計装し、それ以外を無視するだけで、credential dump のステージング、ランサムウェアのスイープ、DPAPI 窃取を、どんな EDR よりも安く捕まえられます。

## どこで発火するか

オブジェクトを所有するホスト上です。ファイル SACL はファイル サーバーで発火します。ローカル レジストリ SACL はワークステーションで発火します。AD オブジェクト SACL は DC で発火します。中央集権的なレコードはありません。機密共有を全社的に可視化するには、それをホストするファイル サーバーから Security を転送する必要があります。これを見落とす人が後を絶ちません。

## レコードのフィールド

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x2a4c8</Data>
<Data Name="ObjectServer">Security</Data>
<Data Name="ObjectType">File</Data>
<Data Name="ObjectName">C:\Windows\System32\config\SAM</Data>
<Data Name="HandleId">0x4d0</Data>
<Data Name="AccessList">%%4416 %%4423</Data>
<Data Name="AccessMask">0x80</Data>
<Data Name="ProcessId">0x1d34</Data>
<Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
<Data Name="ResourceAttributes">-</Data>
```

重要なもの:

- `ObjectType`。`File`、`Key` (レジストリ)、`Process`、`Token`、`Directory`、`Section`。SACL をサポートする任意のオブジェクト クラス。
- `ObjectName`。フル パス。ファイルは Windows パス。レジストリ キーは `\REGISTRY\MACHINE\...` 配下のフル パス (regedit で入力する `HKLM\...` ではない)。
- `AccessList`。試行された内容をデコードされたアクセス権トークンとして。よく使うもの:
  - `%%4416` = ReadData / ListDirectory
  - `%%4417` = WriteData / AddFile
  - `%%4418` = AppendData / AddSubdirectory
  - `%%4419` = ReadEA、`%%4420` = WriteEA
  - `%%4423` = ReadAttributes、`%%4424` = WriteAttributes
  - `%%4425` = DELETE
- `AccessMask`。実際に要求された `STANDARD_RIGHTS_*` とオブジェクト固有権のビット マスク。
- `ProcessName` と `ProcessId`。ハンドルを開いたプロセス。フル プロセス コンテキストには [4688](/ja/blog/event-id-4688-process-creation) または [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) に飛んでください。
- `SubjectLogonId`。発信元セッション、ネットワーク ログオンの場合の送信元 IP、ユーザーには [4624](/ja/blog/understanding-event-id-4624) に飛んでください。

## 4663 を有効化するのは 3 ステップで、1 つを飛ばす人が多い

1. **監査ポリシー**。File System や Registry の *Object Access* サブポリシーを、成功や失敗で有効化。グループ ポリシー、または `auditpol /set /subcategory:"File System" /success:enable /failure:enable`。
2. **オブジェクトの SACL**。GUI ではプロパティの Security タブ、Advanced、Auditing タブ。あるいは `Set-Acl`、`icacls /audit`。どのプリンシパル、どの権利、成功/失敗のどちらを監査するかを指定。
3. **レジストリの場合**、regedit のキーのアクセス許可、Advanced、Auditing から同じ流れ。

(1) がなければレコードは書かれません。(2) がなければ Windows は何を監査したいか知りません。(3) がなければファイルしか監査していないことになります。人々が最もよく飛ばすのは (2) です。ステップ (1) だけで足りるように感じるからです。足りません。

すべてのサーバーで本領を発揮する SACL:

- `C:\Windows\System32\config\SAM`、`SECURITY`、`SYSTEM`。`Everyone : ReadData : Success` を監査。これらを `LocalSystem` 以外が読むのは credential dumping です。
- `C:\Windows\Temp` と `%TEMP%` の `*.dmp` ファイル。`Everyone : WriteData : Success` を監査。ここに `.dmp` を書くプロセスは、クラッシュ後の Windows か、Mimikatz オペレーターです。
- `C:\ProgramData\Microsoft\Crypto\RSA` と `C:\Users\*\AppData\Roaming\Microsoft\Protect`。DPAPI マスター キー ディレクトリ。`ReadData : Success` を監査。ユーザー自身のセッション外でこれらを読むのはシークレットを盗んでいます。
- `HKLM\SECURITY` と `HKLM\SAM`。レジストリ相当。同じ監査。
- 機密ファイル共有: 経理、法務、給与。ランサムウェア スイープと一括削除を捕えるため `WriteData + DELETE : Success` を監査。

## 実際に捕まえるパターン

### SAM または SYSTEM ハイブの読み取り

`ObjectName` が `\config\SAM`、`\config\SECURITY`、または `\config\SYSTEM` で終わり、`ProcessName` が `services.exe`、`lsass.exe`、`wininit.exe` 以外で、`SubjectUserSid` が `S-1-5-18` でない 4663。これは `reg save HKLM\SAM`、シャドウ コピーに対する `esentutl /y`、またはハイブにファイル レベルでアクセスする任意の credential dumping ツールです。残されたバックアップ ハイブ ファイルがないか [registry](https://www.registryparser.com) を相互チェックしてください。

### LSASS minidump の書き込み

`C:\Windows\Temp\`、`C:\ProgramData\`、または `%TEMP%` の `.dmp` ファイルへの `WriteData` の 4663 で、`ProcessName` が `rundll32.exe`、`procdump*.exe`、または `comsvcs.dll` を呼ぶもの。教科書は `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> lsass.dmp full`。[4688](/ja/blog/event-id-4688-process-creation) を相互参照して `CommandLine` を見てください。EDR が寝ていてもこの 4663 が捕まえます。

### ランサムウェアの暗号化スイープ

機密共有内のファイルに対する、数秒以内のすべて同じ `SubjectLogonId` と `ProcessName` からの、`WriteData + DELETE` を含む `AccessMask` の 4663 が多数。実際のバックアップ プロセスはスロットルされた測定可能なパターンでファイルに触れます。ランサムウェアはディスクが許す限り速くディレクトリ ツリーをスイープします。形でわかります。

### DPAPI マスター キーの窃取

ユーザー自身のセッション以外のプロセスによる `\AppData\Roaming\Microsoft\Protect\<sid>\` 配下のファイルへの `ReadData` の 4663。決定的な兆候は、`SubjectUserSid` がパスに埋め込まれた SID と*異なる*こと。

### Group Policy Preferences パスワード ファイルの読み取り

`\SYSVOL\<domain>\Policies\*\Groups.xml`、または `Services.xml`、`Drives.xml`、`ScheduledTasks.xml` にマッチするファイルへの `ReadData` の 4663。これは `Get-GPPPassword` です。古いテクニックです。SYSVOL ファイルはレガシー ドメインに今もよく残っており、MSDN から難読化された AES キーを拾ってドメイン資格情報を持って帰る人が、想像以上にいます。

## Sigma: SAM ハイブの読み取り

```yaml
title: SAM Hive Read from Disk (Credential Dumping)
id: 5e1f9a3a-49a3-4f31-9c2e-8f5b1c2d3a4f
status: stable
description: A non-system process opened the SAM/SECURITY/SYSTEM registry hive file with read access.
references:
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/techniques/T1003/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectType: 'File'
    ObjectName|endswith:
      - '\config\SAM'
      - '\config\SECURITY'
      - '\config\SYSTEM'
    AccessList|contains: '%%4416'
  filter_system:
    SubjectUserSid: 'S-1-5-18'
    ProcessName|endswith:
      - '\services.exe'
      - '\lsass.exe'
      - '\wininit.exe'
      - '\smss.exe'
  condition: selection and not filter_system
falsepositives:
  - Volume Shadow Copy backup processes (track by ProcessName)
  - Legitimate forensic agents (Velociraptor, GRR)
level: high
tags:
  - attack.credential_access
  - attack.t1003.002
```

## KQL: ランサムウェアの暗号化スイープ

```kusto
SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where AccessMask in ("0x10000", "0x40000", "0x100", "0x2")  // DELETE, WriteData
| summarize Files=dcount(ObjectName), Sample=any(ObjectName)
    by SubjectLogonId, ProcessName, bin(TimeGenerated, 1m)
| where Files >= 100
| order by TimeGenerated desc
```

1 つのログオン セッションで分あたり 100 個の異なるファイルが書き込まれるか削除されているのはスイープです。終わり。

## Splunk: DPAPI マスター キー アクセス

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## ATT&CK マッピング

- T1003.002 OS Credential Dumping: Security Account Manager。SAM ハイブの読み取り。
- T1003.004 LSA Secrets。SECURITY ハイブの読み取り。
- T1003.001 LSASS Memory。`.dmp` 書き込み (プロセス コンテキストと組み合わせ)。
- T1555.004 Credentials from Password Stores: Windows Credential Manager。`\AppData\Local\Microsoft\Credentials\` へのアクセス。
- T1552.006 Unsecured Credentials: Group Policy Preferences。SYSVOL の `Groups.xml` 読み取り。
- T1486 Data Encrypted for Impact。一括 `WriteData + DELETE` パターン。
- T1565.001 Stored Data Manipulation。監視対象データ共有への任意書き込み。

## SACL ボリュームの罠

`Everyone : All access : Success+Failure` を忙しいディレクトリに設定すると、分あたり数十万の 4663 が出てコレクションを埋もれさせます。SACL は精密機器です。監査するのは:

- 関心のあるアクセス種別だけ。資格情報ストアには ReadData。データ共有には WriteData + DELETE。両方同時はまれ。
- 成功のみ。失敗はこのコーパスでは稀で、興味深いことも稀。
- ドライブ全体ではなく特定ファイル。`C:\Windows\System32\config\` 全体ではなく SAM ファイル。`D:\` 全体ではなく HR 共有。
- 可能なら特定のプリンシパル。SAM クラスのオブジェクトについては正当なアクセスは `LocalSystem` のみなので `Everyone` で OK。共有データについては、実際にデータに触れるプリンシパルだけを監査。

5 つの高価値オブジェクトの調整された SACL は、ホストあたり 1 日 50 〜 200 レコードを生成します。完全に扱えます。

## 攻撃と見分けがつかない誤検知

- Volume Shadow Copy バックアップは、バックアップ ウィンドウ中に密な 4663 トラフィックを生成します。バックアップ オーケストレータの `ProcessName` にタグを。
- アンチウイルスのオン アクセス スキャンは、対象ディレクトリのすべてのファイルを開きます。AV 製品のサービス アカウントは、素朴な 4663 ルールを支配します。SID でホワイトリスト化を。
- インデックス サービス (Windows Search) は `ReadAttributes` 経由でメタデータに触れます。通常 `AccessList` でフィルタ可能。
- バックアップ ステージのリストアはランサムウェア書き込みのように見えます (多数のファイル、1 つのプロセス、ディレクトリ内)。プロセスが違いを教えます。
- Defender のリアルタイム スキャンはすべてを読みます。広く監査するとノイズを支配します。

## 4663 が教えないこと

- アクセスの内容。ファイルが読まれた/書かれたことは見えますが、何が読まれた/書かれたかは見えません。それには EDR か FIM。
- アクセスが起きた理由。ユーザー意図と相関させるには、呼び出しプロセスのフル コンテキストのため [4688](/ja/blog/event-id-4688-process-creation) または [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) と組み合わせ。
- 閉じられたハンドル。4663 はハンドル *open* で発火します。close イベントは 4658 で、攻撃検知に有用なことはまれです。
- ネットワーク パスを透過的には。共有への SMB アクセスは*サーバー*で 4663 を発火します。クライアントには何も見えません。サーバー側の収集が必要です。
- 既定で失敗アクセス。多くのショップは Success のみ監査します。阻止された試行を本当に気にする場合のみ Failure を構成してください。

## タイムラインでの 4663 の位置

古典的な LSASS 資格情報ダンプのチェーン:

1. [4624](/ja/blog/understanding-event-id-4624)。管理者ログオン、LogonType 3 または 10。
2. [4672](/ja/blog/event-id-4672-special-privileges)。セッションで SeDebugPrivilege が付与。
3. [4688](/ja/blog/event-id-4688-process-creation)。`rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`。
4. **4663**。`rundll32.exe` による `C:\Windows\Temp\lsass.dmp` への `WriteData`。フォレンジックの金。ステージング エクスフィルの証拠。
5. [4688](/ja/blog/event-id-4688-process-creation)。ファイル移動またはアーカイブ (オペレーターがダンプを抽出)。
6. [1102](/ja/blog/event-id-1102-cleared-log)。Security ログのクリア。一部のオペレーターはこれをします。多くは忘れます。

ステップ 4 はチェーン内で最も安価で具体的な信号です。credential 窃盗のアーティファクトを名前で、ディスク上で、呼び出しプロセス付きで直接特定します。SAM ハイブの読み取り、DPAPI マスター キーのアクセス、SYSVOL の Groups.xml の読み取りも同じように動作します。

## 参考資料

- [4663 の Microsoft ドキュメント](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [SpecterOps: SACLs for Detection](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)

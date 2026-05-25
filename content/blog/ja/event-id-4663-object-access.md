---
title: "Event ID 4663 を解読する:SACL によるファイル & レジストリ アクセス監査"
description: "4663 はオブジェクト アクセスごとの監査レコード。適切なファイルとキーに SACL を設定すれば、誰が何に触れたかをバイト単位で記録できる — ランサムウェア、データ持ち出し、資格情報ストア窃取に有効。"
date: "2026-05-24"
---

Event ID **4663** — 「オブジェクトへのアクセスが試行されました」 — は、監査対象のファイル、レジストリ キー、またはカーネル オブジェクトが、その System Access Control List（SACL）にマッチする方法でアクセスされるたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に記録されます。ほとんどの Security レコードと違い、4663 は単独では何も出力しません — 4663 のレコードを生むには、対象オブジェクトの SACL を*設定する*必要があります。これによりデフォルトでは軽量、チューニングすれば破壊的に効果的になります。

4663 で 1 つだけ監査するなら、資格情報ストアと高価値データ共有へのアクセスを監査してください。シグナル対ノイズ比は監査カタログ全体でも最良の部類です。

## どこで発火するか

オブジェクトを所有するホスト上で常に発火します — ファイル SACL ならファイル サーバ、ローカル レジストリ SACL ならワークステーション、AD オブジェクト SACL なら DC。中央集約レコードはありません。重要な共有について全社的に可視化したいなら、その共有をホストするファイル サーバから `Security` を転送する必要があります。

## レコードの中身

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

各フィールド。

- **`ObjectType`** — `File`、`Key`（レジストリ）、`Process`、`Token`、`Directory`、`Section`、または SACL をサポートする任意のオブジェクト クラス。
- **`ObjectName`** — フル パス。ファイルなら Windows パス、レジストリ キーなら `\REGISTRY\MACHINE\…` 配下のフル パス（注意:regedit に入力する `HKLM\…` 表記ではありません）。
- **`AccessList`** — 何が試行されたか。デコード済みのアクセス権名のリスト（`%%NNNN` トークン 1 つにつき 1 つ）。よく見るデコード値:
  - `%%4416` = `ReadData (or ListDirectory)`
  - `%%4417` = `WriteData (or AddFile)`
  - `%%4418` = `AppendData (or AddSubdirectory)`
  - `%%4419` = `ReadEA` / `%%4420` = `WriteEA`
  - `%%4423` = `ReadAttributes` / `%%4424` = `WriteAttributes`
  - `%%4425` = `DELETE`
- **`AccessMask`** — 実際に要求された `STANDARD_RIGHTS_*` とオブジェクト固有の権利の生のビットマスク。
- **`ProcessName`** + **`ProcessId`** — ハンドルを開いたプロセス。完全なプロセス コンテキストには [4688](/ja/blog/event-id-4688-process-creation) / [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) へピボット。
- **`SubjectLogonId`** — 元のセッションへピボットするための鍵。ネットワーク ログオンなら送信元 IP、ユーザーを取得するため [4624](/ja/blog/understanding-event-id-4624) へ。

## 4663 の設定 — 実際に手間がかかる部分

設定は 3 層あり、どれを欠いてもレコードは出ません。

1. **監査ポリシー**:*オブジェクト アクセス → ファイル システムの監査*および/または *レジストリの監査*を success / failure で有効化。グループ ポリシーまたは `auditpol /set /subcategory:"File System" /success:enable /failure:enable` 経由。
2. **オブジェクトへの SACL**:右クリック → プロパティ → セキュリティ → 詳細設定 → 監査タブ（Windows GUI）、または `Set-Acl` / `icacls /audit`。*どのプリンシパル*（多くは `Everyone` か `Authenticated Users`）、*どの権利*、*success / failure / 両方*を監査するかを指定。
3. **レジストリの場合**:同じフロー。`regedit` → キー → アクセス許可 → 詳細設定 → 監査からアクセス。

(1) がなければレコードは決して書かれません。(2) がなければ Windows は何を監査したいのか知りません。(3) がなければファイルしか監査されません。

すべてのサーバに設定すべき SACL。

- **`C:\Windows\System32\config\SAM`**、**`SECURITY`**、**`SYSTEM`** — ローカル資格情報ストア。`Everyone : ReadData : Success` を監査。`LocalSystem` 以外がこれらを読むのは資格情報ダンプの試みです。
- **`%TEMP%\lsass.dmp`** および `C:\Windows\Temp` の任意の `*.dmp` — プロセス minidump。`Everyone : WriteData : Success` を監査。ここに `.dmp` を書き込むプロセスはクラッシュ ダンプ（Windows）か Mimikatz オペレータ（それ以外全員）のどちらかです。
- **`C:\ProgramData\Microsoft\Crypto\RSA`** および **`C:\Users\*\AppData\Roaming\Microsoft\Protect`** — DPAPI マスタ キー ディレクトリ。`ReadData : Success` を監査。ユーザー自身のセッション外からこれらを読む者は保護されたシークレットを窃取しています。
- **`HKLM\SECURITY`** および **`HKLM\SAM`** — レジストリの等価物。`ReadData : Success` を監査。
- **重要なファイル共有** — 財務、法務、給与。`WriteData + DELETE : Success` を監査して、ランサムウェアの暗号化スイープと大量削除を捕捉。

## トリアージ パターン

### 1. SAM / SYSTEM ハイブ読み取り

`ObjectName` が `\config\SAM`、`\config\SECURITY`、`\config\SYSTEM` で終わり、`ProcessName` が `services.exe` / `lsass.exe` / `wininit.exe` でなく、`SubjectUserSid` が `S-1-5-18` でない 4663。これは `reg save HKLM\SAM`、`esentutl /y`、`vssadmin create shadow + copy`、またはファイル レベルのハイブ アクセスを持つ任意の資格情報ダンプ ツールです。

### 2. LSASS ダンプ ファイルの書き込み

`C:\Windows\Temp\`、`C:\ProgramData\`、または `%TEMP%` の `.dmp` ファイルに対する 4663 `WriteData`。`ProcessName` が `rundll32.exe`、`procdump*.exe`、`comsvcs.dll` 関連の呼び出し元、または改名されたバイナリ。これは LSASS-minidump パターンです。`CommandLine` を見るため [4688](/ja/blog/event-id-4688-process-creation) と相互参照 — `comsvcs.dll MiniDump` が最も一般的な形式です。

### 3. ランサムウェアの暗号化スイープ

秒単位で重要共有内のファイルに対し `AccessMask` が `WriteData + DELETE` を含む 4663 が多数、すべて同じ `SubjectLogonId` と `ProcessName` から。本物のバックアップ プロセスは測定可能でスロットルされたパターンでファイルに触れますが、ランサムウェアはディスクが許す限りの速度でディレクトリ ツリーをスイープします。

### 4. DPAPI マスタ キー窃取

`\AppData\Roaming\Microsoft\Protect\<sid>\` 配下のファイルに対する 4663 `ReadData` で、ユーザー自身のセッション以外のプロセスからのもの。古典的なパターンは `SubjectUserSid` がパス内の SID と*異なる*こと。

### 5. グループ ポリシー設定ファイル内のパスワード読み取り

`\SYSVOL\<domain>\Policies\*\Groups.xml`（または `Services.xml`、`Drives.xml`）にマッチするファイルへの 4663 `ReadData`。これは `Get-GPPPassword` 攻撃で、古いですが SYSVOL ファイルはレガシー ドメインに残っていることが多いです。

## サンプル Sigma ルール — SAM ハイブ読み取り

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

## サンプル KQL — ランサムウェア暗号化スイープ

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

1 ログオン セッション下で 1 分あたり 100 個の distinct ファイルへの書き込み / 削除はスイープ、議論の余地なし。

## サンプル Splunk — DPAPI マスタ キー アクセス

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## ATT&CK マッピング

- **T1003.002 — OS Credential Dumping: Security Account Manager**:SAM ハイブ読み取り。
- **T1003.004 — OS Credential Dumping: LSA Secrets**:SECURITY ハイブ読み取り。
- **T1003.001 — OS Credential Dumping: LSASS Memory**:`.dmp` 書き込み（プロセス コンテキストと組み合わせて）。
- **T1555.004 — Credentials from Password Stores: Windows Credential Manager**:`\AppData\Local\Microsoft\Credentials\` へのアクセス。
- **T1552.006 — Unsecured Credentials: Group Policy Preferences**:SYSVOL `Groups.xml` 読み取り。
- **T1486 — Data Encrypted for Impact**:大量の WriteData + DELETE パターン（ランサムウェア）。
- **T1565.001 — Stored Data Manipulation**:監視対象データ共有への任意のファイル書き込み。

## ボリューム管理 — SACL の罠

忙しいディレクトリに素朴に `Everyone : All access : Success+Failure` を設定すると、毎分数十万件の 4663 が生成され、コレクションが埋まります。SACL は精密機器です。監査するのは:

- **気にするアクセス タイプだけ**（資格情報ストアには `ReadData`、データ共有には `WriteData + DELETE`、両方は稀）。
- **success のみ** — failure はより稀でほぼ興味なし。
- **特定のファイル**、ドライブ全体ではなく。`C:\Windows\System32\config\` 全体ではなく SAM ファイル。`D:\` 全体ではなく HR 共有。
- 可能な限り**特定のプリンシパル** — SAM クラスのオブジェクトでは正当なアクセスはどのみち `LocalSystem` だから `Everyone` で OK、共有データなら実際にデータに触れるプリンシパルのみを監査。

5 つの高価値オブジェクトに対する適切にチューニングされた SACL は、ホストあたり 1 日 50〜200 レコードを生成 — 完全に扱える量です。

## 攻撃そっくりの誤検知

- **Volume Shadow Copy**（VSS）バックアップは、バックアップ ウィンドウ中に高密度の 4663 トラフィックを生成。バックアップ オーケストレータの `ProcessName` にタグを付ける。
- **アンチウイルスのオンアクセス スキャン**は対象ディレクトリのすべてのファイルを開く。AV 製品のサービス アカウントが素朴な 4663 ルールを支配します。SID でホワイトリスト化。
- **インデックス サービス**（Windows Search、Spotlight 風）は `ReadAttributes` でメタデータに触れる — 通常 `AccessList` でフィルタ可能。
- **バックアップから段階的なリストア**はランサムウェア書き込みのように見える（多くのファイル、1 プロセス、1 ディレクトリ内）が、プロセスはバックアップ エージェント。
- **Defender のリアルタイム スキャン**はあらゆるものを読みます。広く監査しすぎると支配的なノイズ源になります。

## 4663 では分からないこと

- **アクセスの内容**:ファイルが読み書きされたことは分かりますが、何を読み書きされたかは分かりません。後者には EDR や FIM（File Integrity Monitoring）製品が必要です。
- **アクセスの理由**:syscall の結果のみ。ユーザーの意図と相関させるには、呼び出しプロセスの完全コンテキストを得るため [4688](/ja/blog/event-id-4688-process-creation) / [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) と組み合わせます。
- **ハンドルのクローズ**:4663 はハンドル*オープン*で発火。クローズ イベントは 4658 で、攻撃検知には稀にしか有用ではありません。
- **ネットワーク パス透過的に**:共有への SMB アクセスは*サーバ*で 4663 を発火させます。クライアントには何も見えません。サーバ側収集が必要です。
- **デフォルトでは failure のアクセス**:多くの現場は `Success` のみを監査。阻止されたアクセス試行を本当に気にする場合のみ `Failure` を設定。

## タイムラインにおける 4663 の位置

古典的な LSASS 資格情報ダンプ連鎖。

1. [**4624**](/ja/blog/understanding-event-id-4624) — 管理者ログオン（LogonType 3 または 10）。
2. [**4672**](/ja/blog/event-id-4672-special-privileges) — セッションに SeDebugPrivilege を付与。
3. [**4688**](/ja/blog/event-id-4688-process-creation) — `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`。
4. **4663** — `rundll32.exe` による `C:\Windows\Temp\lsass.dmp` への `WriteData`。**フォレンジック ゴールド — エクスフィル ステージングの証拠。**
5. [**4688**](/ja/blog/event-id-4688-process-creation) — ファイル移動 / アーカイブ（ダンプを抽出するオペレータ）。
6. [**1102**](/ja/blog/event-id-1102-cleared-log) — Security ログのクリア（一部のオペレータはこれを行う。多くは忘れる）。

ステップ 4 の 4663 は連鎖中で最も安価かつ最も特異なシグナルです — 資格情報窃取のアーティファクトを名前付きで、ディスク上で、呼び出しプロセスとともに直接特定します。SAM ハイブ読み取り、DPAPI マスタ キー アクセス、SYSVOL Groups.xml 読み取りも同様に機能します。

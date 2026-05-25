---
title: "Event ID 7045 を解読する:永続化シグナルとしてのサービス インストール"
description: "サービス作成は最も騒がしい永続化手法の一つ。Event 7045 は全インストールを捕捉する — 3 つのフィールドを読めばその大半を捉えられる。"
date: "2026-05-17"
---

Event ID **7045** — 「システムにサービスがインストールされました」 — は、Service Control Manager が新規サービスを登録するたびに [`System` チャネル](/ja/blog/what-is-an-evtx-file) に発火します。素の構成（ドライバ インストール、更新）ではノイズが多いですが、定常運用の企業環境では十分静かなので異常が目立ちます。MITRE ATT&CK の最も引用される永続化手法の 1 つでもあります:T1543.003。

## レコードの中身

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

5 つのフィールド、そのうち IR に重要なのは 3 つ。

## 最初に読むべき 3 つのフィールド

**`ImagePath`** は単体で最も有用なフィールドです。正当なサービスは `C:\Windows\System32\`、`C:\Program Files\`、または `C:\Program Files (x86)\` の下に存在します。バイナリが `C:\Windows\Temp\`、`C:\Users\<user>\AppData\`、`C:\ProgramData\`、またはランダム名のディレクトリにあるサービスは要確認です。`ImagePath` は `cmd.exe /c …` や `powershell.exe -e …` の行になることもあります — それらはほぼ常に悪意です。正当なサービスはシェルアウトしません。

**`AccountName`** は通常 `LocalSystem` です。組織のパターンに合わないドメイン ユーザーや特定サービス アカウント下でインストールされたサービスは異常です。

**`StartType`** が `auto start` ならサービスは起動ごとに動作します。`demand start` は手動です。永続化はほぼ常に `auto start` を欲しがります。ワンショット横展開実行は `demand start` を使い後始末する可能性があり — 7045 が唯一残るアーティファクトになります。

## 横展開実行のパターン

攻撃者が `PsExec` または SCM を使って別ホストでリモート実行するツールを動かすと、*ターゲット*ホスト上に `%SystemRoot%\PSEXESVC.exe`（デフォルト）または改名された等価物のような `ImagePath` を持つ 7045 が現れます。サービスは現れ、動作し、しばしば数秒以内に削除されます。7045 はサービス自体が消えた後ずっと残る指紋です。

`ImagePath` が `.exe` で終わる 7045 の数秒後に特定の送信元ホストからの [4624 LogonType **3**](/ja/blog/understanding-event-id-4624) は、教科書的な PsExec シグネチャです。SMBExec、WMIExec、Impacket の `psexec.py` などのバリアントはわずかに異なる `ImagePath` を生成しますが、全体のパターンは同じです。

## 7045 では分からないこと

7045 は*インストール*で発火し、以降の起動ごとには発火しません。サービスが実際に動いているのを見るには 7036（「サービスは running 状態に入った」）が必要です。基底のプロセスを見るには [Sysmon イベント 1](/ja/blog/sysmon-event-id-1-process-create) または対応する `Image` パスの [4688](/ja/blog/event-id-4688-process-creation) が必要です。

監査ログ開始*前*にインストールされたサービス（例:OS インストール中）には 7045 は存在しません — それらはレジストリの `HKLM\SYSTEM\CurrentControlSet\Services\` に存在し、イベント ログからではなくそこから列挙する必要があります。

## トリアージ ワークフロー

1. System チャネルを `EventID:7045` でフィルタ。
2. `ImagePath` でソートまたはピボット — 標準インストール パスの外はすべて疑わしい。
3. 各疑わしいものについて、タイムスタンプ + 送信元ホストでマッチする 4624 を取得 — インストールに使われた資格情報を見つける。
4. `Image` が `ImagePath` にマッチする Sysmon イベント 1 を取得して実際の実行を見る。
5. [**7036**](/ja/blog/event-id-7036-service-state) / 7034 / 7035 シーケンスがワンショット実行か永続的サービスかを示すか確認。

## サンプル Sigma ルール — 非標準パスからのサービス インストール

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory — common for persistence and PsExec-style execution.
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1569/002/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  suspicious_path:
    ImagePath|contains:
      - '\Windows\Temp\'
      - '\Users\'
      - '\ProgramData\'
      - '\AppData\'
      - '\Public\'
  shell_image:
    ImagePath|contains:
      - 'cmd.exe /c'
      - 'cmd /c'
      - 'powershell'
      - 'pwsh'
      - 'rundll32'
      - 'mshta'
  condition: selection and (suspicious_path or shell_image)
falsepositives:
  - Software installers that bootstrap services from a staging directory
  - Custom enterprise tooling deployed under ProgramData
level: high
tags:
  - attack.persistence
  - attack.t1543.003
```

## サンプル KQL — PsExec 横展開実行の指紋

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]);
let logons =
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
    | project LogonTime=TimeGenerated, LogonHost=Computer, LogonIp=IpAddress,
              LogonAccount=AccountName;
installs
| where ImagePath endswith ".exe"
| join kind=inner logons on $left.Host == $right.LogonHost
| where LogonTime between (InstallTime - 30s .. InstallTime + 30s)
| project InstallTime, Host, ServiceName, ImagePath, LogonIp, LogonAccount
| order by InstallTime desc
```

同じホスト上で 7045 の 30 秒以内の 4624 LogonType-3 は教科書的な PsExec シグネチャです。

## サンプル Splunk — 異常なサービス インストーラ

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## ATT&CK マッピング

- **T1543.003 — Create or Modify System Process: Windows Service**:目玉のマッピング。攻撃者制御バイナリ下で長期実行されるサービス。
- **T1569.002 — System Services: Service Execution**:純粋にリモート実行の手段として使われる短命サービス（PsExec、SMBExec、SCM ベースの横展開）。
- **T1078 — Valid Accounts**:インストール プリンシパルが資格情報を盗まれたドメイン管理者の場合。
- **T1036.005 — Masquerading: Match Legitimate Name or Location**:表示名は実 Microsoft サービスを模倣するがバイナリは別場所にあるサービス。

## 攻撃そっくりの誤検知

- **ソフトウェア インストーラ**（Chocolatey、MSI ブートストラッパ）は、最終バイナリを移動する前にステージング ディレクトリからサービスをインストールすることが多いです。最終インストールはクリーンでもステージング パスから 7045 が発火します。
- **EDR / AV エージェント**はセットアップの一環としてサービスをインストール。ベンダの `ImagePath` は安定して署名済み。ベースライン化。
- **一部の Microsoft 更新**は一時的なサービシング サービスをインストール。短命で `LocalSystem` から。
- **コンテナ / Hyper-V** ワークロードは VM ごとに一時的なサービスを登録することがあります。

シグナルは*ワンオフ*のユーザー書き込み可能パスへのインストールで、*非管理者または非標準*インストーラによるもの。`C:\Program Files\` 内の署名済みインストーラ サービスは攻撃ではありません。

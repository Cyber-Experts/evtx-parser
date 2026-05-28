---
title: "Security.evtx でラテラル ムーブメントを検知する"
description: "実際の敵対者ツールが Windows 環境でホスト間を移動する仕組みと、PsExec、Impacket、WMIExec を捕える Security.evtx の正確なイベント ID の組み合わせ。"
date: "2026-05-27"
tags:
  - evtx
  - lateral-movement
  - dfir
  - incident-response
  - threat-hunting
author: "Florian Amette"
---

ラテラル ムーブメントは、多くの侵入が「足がかりを得た」から「ドメインを掌握した」へと進むポイントです。同時に、Windows のログが最も有用かつ最も誤誘導しやすい場所でもあります。必要なイベントはすべて `Security.evtx` と `System.evtx` にあります。単独で読んでもどこにも辿り着けません。正しいペアで、正しいクロスホスト相関で読むことが、有用なタイムラインと `4624` の壁との違いを生みます。

これは調査の中で、私がスクロールをやめて `LogonId` で grep を始める部分です。

## 骨格: 攻撃者が移動するときに起きること

普遍的なラテラル ムーブメントのパターンはありませんが、普遍的な*形*はあります。

1. 攻撃者がホスト A からホスト B に対して認証します。現在のユーザーのトークン (pass-the-hash、pass-the-ticket、または盗まれた Kerberos TGT/TGS) を使うか、別のアカウントの明示的な資格情報を使います。
2. ホスト B 上で何かがペイロードを実行します。サービス、スケジュールド タスク、WMI プロセス作成、リモート PowerShell セッション、または DCOM 呼び出し。
3. ツール、シークレット、または次のホップを取りに戻ります。

各ステップがイベントを残します。問題は、正しいものを見ているか、ツール群が計装されているかです。

## 4624 LogonType 3 は玄関

成功したネットワーク ログオン (`EventID=4624` かつ `LogonType=3`) は、ログ内で最も一般的なラテラル ムーブメント プリミティブです。同時に Windows が生成する中で最もノイジーなイベントでもあります。500 席のオフィスのファイル サーバーは、1 日にこれを何万件も、すべて正当に生成します。`LogonType=3` だけでフィルタしても、どこにも行けません。

行けるようにするもの:

- イベント データの `IpAddress` と `WorkstationName`。異常はここに集中します。02:14 UTC に別のサブネットからサーバーにログオンするワークステーションは、何でもないとは言えません。
- `AuthenticationPackageName` と `LogonProcessName`。Kerberos 環境のドメイン参加ホスト間の NTLM ログオン (`NTLM` / `NtLmSsp`) は、既定で疑わしい。クリーンな Kerberos 環境は、ドメイン内認証では Kerberos のみで、NTLM は非 DNS 名アクセスとレガシーへのフォールバックに限定されるべきです。
- `TargetUserName` のパターン。対話的にログオンするサービス アカウントは赤旗。ワークステーションにログオンするドメイン管理者アカウントは赤旗。

欲しい軸: 興味深い `4624 Type 3` のすべてを、同じ `TargetLogonId` の対応する `4672` (特権) とペアにします。ログオンが管理者特権を得たなら、資格情報濫用の候補があります。そうでないなら、攻撃者はより低い特権のトークンで動作しており、時間があります。

## 4648 は防御側が最も活用しない

`4648` (「明示的な資格情報を使ってログオンが試行されました」) は、アカウント A として動作するプロセスが、アカウント B の資格情報を呼び出して何かをするたびに生成されます。これが帰属に欲しいイベントです。`mimikatz` や `Rubeus` がチケットを注入し、オペレーターが `net use \\TARGET /user:CORP\admin <pass>` を実行すると、発信元ホストに両方のアカウントと対象を示す `4648` が出ます。

重要なフィールド:

- `SubjectUserName` / `SubjectLogonId` — 誰が開始したか。
- `TargetUserName` / `TargetServerName` — 誰の資格情報で、何に対して。
- `ProcessName` — どのバイナリが呼び出したか。`cmd.exe`、`powershell.exe`、`wmic.exe`、`psexec.exe`、`wmiprvse.exe` (WMI ベース実行用)、そして増えつつある `pwsh.exe` が定番の容疑者です。

`4648` は侵害されたホストと次のホップをつなぐリンクです。容疑のあるホストがあれば、まずその Security ログから `4648` をダンプしてください。攻撃者がどの資格情報を持っているか、どこで使おうとしたかを、時系列で 1 箇所にまとめて教えてくれます。

## 4672 と特権の物語

`4672` は、少なくとも 1 つのセンシティブな特権 (`SeDebugPrivilege`、`SeTcbPrivilege`、`SeBackupPrivilege` など) を持つことになるログオンに対し、`4624` の直後に出力されます。`Administrators`、`Domain Admins`、またはトークン昇格特権を持つアカウントのメンバーのすべてのログオンに対して生成されます。

これはタグであって発見ではないと扱ってください。有用なクエリは「非 DC ソース IP からの `4624 Type 3` が 60 秒以内に続くすべての `4672` を見せて」です。これは、発行すべきでないワークステーションからの管理者トークン利用を浮かび上がらせます。有用でないクエリは「すべての `4672` を見せて」で、これは全サーバーの全サービス開始を返します。

## 4697 と 7045: リモート実行としてのサービス

PsExec、Impacket の `psexec.py`、`smbexec.py` は、ターゲットの `ADMIN$` 共有にサービス バイナリを書き、サービス コントロール マネージャー経由で登録し、起動し、破棄することで機能します。残るもの:

- オブジェクト アクセス監査が有効なら、書かれたファイル名とともに `\\target\ADMIN$` へのアクセスを示すターゲットの `5145`。
- サービス インストールを示す `System.evtx` の `7045`。サービス バイナリ パスとサービス名がイベント データに入ります。PsExec は既定で `%SystemRoot%` の `PSEXESVC`、Impacket は両方をランダム化し、バージョンによってパターンが異なり、よく文書化されています。
- システム監査ポリシーが設定されていれば、同じサービス インストールに対する `Security.evtx` の `4697`。
- オペレーターの送信元ワークステーションからの `4624 Type 3`。

シグネチャは*組み合わせ*です: 異常な送信元からの `4624 Type 3`、その直後に `ADMIN$` への `5145`、その直後にあるべきでない場所にバイナリがあるサービスの `7045`。各イベント単独ではあり得る話。秒単位で、同じ `LogonId` でつながっている組み合わせは違います。

`7045` で目を引くべきサービス名: ランダムな 8 文字の小文字列 (Impacket のデフォルト)、`PSEXESVC` (PsExec のデフォルト)、`WinExec` やその派生、`C:\Windows\` 配下で署名されておらずシステムの通常サービス セットにないバイナリ パスを持つもの。

## 5140 と 5145: SMB 共有アクセスの詳細

`5140` は共有がアクセスされたことを記録し、`5145` は共有内でアクセスされたファイル名を、共有のオブジェクト アクセス監査が有効な場合に限り記録します。ノイズのために多くの環境で `5145` は有効化されていません。同時にインシデント時にそれがあればよかったと願う環境も多いです。

ラテラル ムーブメントでは、重要な `5145` イベントは異常なソースからの `ADMIN$`、`C$`、`IPC$`、そしてあらゆる `SYSVOL`/`NETLOGON` パスへのアクセスです。`psexec.py` は `\\target\ADMIN$\<random>.exe` に書き込むことでサービス バイナリを置きます。`secretsdump.py` は `\\target\C$\Windows\System32\config\SAM` (そして SYSTEM、SECURITY) を読みます。それぞれが目立つはずの `RelativeTargetName` を持つ `5145` です。

`5145` をターゲット上の [USN journal](https://www.usnparser.com) とペアにしてください。ジャーナルには同じタイムスタンプで同じファイルの `FILE_CREATE` があり、ファイルが実際に到着したことのセカンド ソース確認と、追跡できる [MFT](https://www.mftparser.com) レコード参照が得られます。

## ラテラル ムーブメント ベクトルとしての WMI

WMI ベースのリモート実行 (`wmic /node:... process call create`、Impacket の `wmiexec.py`、PowerShell の `Invoke-WmiMethod`) は、サービスを設置しないため、Security.evtx だけでは見つけにくいです。得られるもの:

- ターゲット上の `4624 Type 3`。
- ターゲット上で `WmiPrvSE.exe` を親とするプロセス作成。Sysmon があるなら Sysmon `EventID=1`。`4688` でも、コマンドライン監査が有効なら同じ絵です。
- コンシューマを示す `Microsoft-Windows-WMI-Activity%4Operational.evtx` の WMI イベント。

Sysmon がない場合、WMI ベースのラテラル ムーブメントはデフォルト設定のイベント ログではほぼ見えません。これがすべての構成ベースラインが Sysmon を強く推す理由の 1 つです。

## ホスト間の相関

ラテラル ムーブメントはグラフ問題です。ホスト A 上で、ホスト B とアカウント `corp\admin` を指す `4648` は 1 つのエッジです。ホスト B 上の、ホスト A の IP からの、`TargetUserName=admin` を持つ対応する `4624 Type 3` は、同じエッジの反対側です。DC 上の、`admin@CORP` から `cifs/hostB` のチケット要求を示す `4769` (Kerberos サービス チケット) は、3 人目の証人です。

実務では、これらすべてが必要です:

- 送信元ホストの `Security.evtx` からのログオン イベント。
- ターゲット ホストの `Security.evtx` からのログオン イベント。
- ドメイン コントローラーの `Security.evtx` からの TGT (`4768`) と TGS (`4769`) イベント。
- 任意の WEC コレクターからの転送イベント。ホストのローカル ログがクリアされた場合に唯一の完全コピーを持つことがあります。

ホスト内では `LogonId` で、ホスト間では時刻 + アカウント + IP でつなげます。古典的な JPCERT/CC の論文がこれを詳細に示しており、このトピックに関する最良の無料文書です。

ログ クリアを生き残るホスト側アーティファクトについては、攻撃者ツール実行の証拠としての [Prefetch](https://www.prefetchparser.com)、設置されて削除されたサービス バイナリの痕跡としての [registry](https://www.registryparser.com) の `Services` キー、そしてオペレーターがハンズオン セッションで開いたファイルの証拠としての [LNK files](https://www.lnkparser.com) と [jump lists](https://www.jumplistparser.com) に頼ってください。

## 参考資料

- JPCERT/CC の [「Detecting Lateral Movement through Tracking Event Logs」](https://jpcertcc.github.io/ToolAnalysisResultSheet/)。リファレンスです。2 回読んでください。
- MITRE ATT&CK [Lateral Movement マトリクス](https://attack.mitre.org/tactics/TA0008/) と、テクニックごとのデータ ソース マッピング。
- Impacket の [examples ディレクトリ](https://github.com/fortra/impacket/tree/master/examples)。`psexec.py`、`wmiexec.py`、`smbexec.py` がワイヤ上で実際に何をするかを読んでいないなら、あなたの検知は推測です。

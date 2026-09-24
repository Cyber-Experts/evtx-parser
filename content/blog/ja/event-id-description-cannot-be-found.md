---
title: "「イベント ID の説明が見つかりません」エラーの原因と対処法"
description: "イベント ビューアーでイベント ID の説明が見つからない理由、%%1833 などのコードの意味、そしてオフラインでもイベントを読む方法を DFIR の視点で解説します。"
date: "2026-09-24"
tags:
  - evtx
  - dfir
  - event-viewer
  - troubleshooting
  - windows-event-log
author: "Florian Amette"
faq:
  - question: "「The description for Event ID X from source Y cannot be found」とはどういう意味ですか？"
    answer: "レコード自体は正常です。.evtx のレコードに保存されているのはイベント ID、プロバイダー名、挿入文字列 (EventData / UserData) だけです。イベント ビューアーで普段読んでいる文章は、ログを表示しているマシン上にあるプロバイダーのメッセージ DLL に格納されたテンプレートです。そのプロバイダーが手元のマシンに登録されていなければ文章を組み立てられず、このエラーと生の挿入文字列が表示されます。"
  - question: "イベントのデータは失われたり壊れたりしていますか？"
    answer: "いいえ。すべてのフィールドはレコードに残っています。イベント ビューアーの [詳細] タブ (XML 表示) を開くか、Get-WinEvent、wevtutil、パーサーで EventData のフィールドを読んでください。欠けているのは、それらを包む人間向けの文章だけです。"
  - question: "イベント中の %%1833 は何を意味しますか？"
    answer: "%%1833 はパラメーター メッセージへの参照で、セキュリティ監査プロバイダーのパラメーター メッセージ ファイルである msobjs.dll から解決されます。%%1833 は Impersonation (4624 の ImpersonationLevel フィールド) です。よく見るものとして %%1842 Yes、%%1843 No、%%2313 Unknown user name or bad password、%%1936/%%1937/%%1938 トークン昇格の種類 1/2/3 があります。"
  - question: "別のコンピューターでも説明付きで開けるように .evtx をエクスポートするには？"
    answer: "ソース マシンのイベント ビューアーで [すべてのイベントを名前を付けて保存] を選び、.evtx を指定して、表示情報を含める言語を選択します。イベント ビューアーは .evtx の隣に .MTA ファイルを含む LocaleMetaData フォルダーを書き出します。両方をまとめてコピーしてください。コマンド ラインでは wevtutil archive-log (wevtutil al) で同じことができます。"
  - question: "プロバイダーをインストールせずにイベントを読めますか？"
    answer: "はい。DFIR ではレンダリングされたメッセージが必要になることはまれです。メッセージが表示するはずの値はすべて EventData のフィールドに入っています。evtxparser.com のブラウザー パーサーは、よく使う DFIR イベントに 1 行の説明を表示し、%% コード、NTSTATUS コード、Kerberos 暗号化タイプもファイルをアップロードせずオフラインでデコードします。"
---

疑わしいホストから `Security.evtx` をコピーし、解析用ワークステーションで開くと、すべてのレコードにこう表示されます。

> The description for Event ID 4625 from source Microsoft-Windows-Security-Auditing cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer. If the event originated on another computer, the display information had to be saved with the event.

日本語版 Windows では、同じメッセージは「ソース "Microsoft-Windows-Security-Auditing" からのイベント ID 4625 の説明が見つかりません。」で始まります。その後に `%%2313`、`0xC000006A`、`0x17` といった生の値が並びます。何も壊れておらず、何も失われていません。これはデータの問題ではなく *レンダリング* の失敗です。この記事では、説明文が実際にどこにあるのか、なぜ表示されないのか、必要なときの直し方、そしてトリアージでは多くの場合それが不要な理由を解説します。(すぐにイベントを読める形にしたいなら、[ブラウザー パーサー](/ja) が説明をレンダリングし、これらのコードをオフラインでデコードします。)

## エラーの本当の意味

`.evtx` のレコードには、イベント ビューアーで読む文章そのものは保存されていません。保存されているのは `<System>` ブロック (プロバイダー、イベント ID、時刻、コンピューター) と、`<EventData>` または `<UserData>` 内の **挿入文字列** です ([レコードの中身](/ja/blog/what-is-an-evtx-file))。「An account failed to log on. Subject: … Failure Reason: …」(英語版 Windows の場合) という文章は、`%1`、`%2` のプレースホルダーを含むテンプレートで、イベント プロバイダーの DLL または EXE 内の **メッセージ テーブル リソース** に格納されています。

Windows がそのファイルを探す場所は、プロバイダーの種類によって異なります。

- **従来型 (レガシー) のイベント ソース** は `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>` に登録され、パスは `EventMessageFile` 値に入ります (オプションで `ParameterMessageFile` と `CategoryMessageFile` も)。
- **マニフェスト ベースのプロバイダー** (Vista 以降、`Microsoft-Windows-*` ファミリー) は `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}` に登録されます。`MessageFileName`、`ResourceFileName`、`ParameterFileName` の各値が、コンパイル済みマニフェスト (`WEVT_TEMPLATE` リソース) とメッセージ テーブルを持つバイナリを指します。

ポイントは、**イベント ビューアーはログを表示しているマシン上でメッセージをレンダリングする** ことです。使われるのはそのマシンのレジストリと DLL であり、イベントを書き込んだマシンは表示時には関係ありません。プロバイダーがローカルに登録されていなければテンプレートがなく、エラーと生の挿入文字列が表示されます。

## よくある原因

- **ログが別のホストから来ている。** DFIR の典型例です。ソース ホスト上のサードパーティ エージェント、EDR、SQL Server インスタンス、業務アプリケーションのプロバイダーは、解析用ワークステーションには存在しません。macOS、Linux、クリーンな VM で開いても同じで、Windows のプロバイダーは一切ありません。
- **ソフトウェアがアンインストールされた。** アンインストーラーが DLL を削除しても、古いイベントは引き続きそのソースを参照しています。
- **DLL の欠落、破損、移動。** レジストリが存在しないパスを指している、または `EventMessageFile` が `REG_EXPAND_SZ` ではなく `REG_SZ` で保存されていて `%SystemRoot%` が展開されない。
- **32/64 ビットの不一致。** 32 ビットのインストーラーが `System32` のつもりで DLL を書き込んだ (ファイル システム リダイレクトにより実際には `SysWOW64`) 一方、64 ビットのイベント ログ スタックは登録パスを本物の `System32` として読みます。
- **言語。** プロバイダーのメッセージ テーブルは存在するが表示言語のものがない、あるいはビューアーの言語とは異なる言語の「表示情報付き」エクスポートを開いた。

## %% コード: パラメーター メッセージ

メインの説明がレンダリングされる場合でも、一部のフィールドには単語ではなく `%%1833` や `%%2313` が表示されます。これは **パラメーター メッセージ** への参照で、値はプロバイダーの `ParameterMessageFile` / `ParameterFileName` という 2 つ目のメッセージ テーブル内の ID です。セキュリティ監査プロバイダーの場合、このファイルは `msobjs.dll` です。オフラインではこれらの参照は解決されないままです。覚えておきたい代表的なもの (ラベルは英語版 Windows の表記) は次のとおりです。

| コード | 意味 | 出現箇所 |
|--------|------|----------|
| `%%1833` | Impersonation | 4624 `ImpersonationLevel` |
| `%%1840` | Delegation | 4624 `ImpersonationLevel` |
| `%%1842` / `%%1843` | Yes / No | 4624 `VirtualAccount`、`ElevatedToken` |
| `%%1936` | タイプ 1、完全なトークン (UAC 無効またはビルトイン Administrator) | 4688 `TokenElevationType` |
| `%%1937` | タイプ 2、昇格されたトークン | 4688 `TokenElevationType` |
| `%%1938` | タイプ 3、制限付きトークン | 4688 `TokenElevationType` |
| `%%2307` | Account locked out (アカウントのロックアウト) | 4625 `FailureReason` |
| `%%2310` | Account currently disabled (アカウント無効) | 4625 `FailureReason` |
| `%%2313` | Unknown user name or bad password | 4625 `FailureReason` |
| `%%2080` | Account Disabled | 4720 `UserAccountControl` |
| `%%2082` | 'Password Not Required' - Enabled | 4720 `UserAccountControl` |
| `%%2084` | 'Normal Account' - Enabled | 4720 `UserAccountControl` |
| `%%1537` | DELETE | 4663 `AccessList` |
| `%%4416` / `%%4417` | ReadData / WriteData | 4663 `AccessList` |

`%%2080 %%2082 %%2084` の 3 つ組は、[4720](/ja/blog/event-id-4720-account-created) で新規作成されたアカウントの通常のシグネチャです。[4688](/ja/blog/event-id-4688-process-creation) の `%%1937` は、UAC プロンプトの後に完全な管理者トークンで起動されたプロセスを示します。

16 進値は `%%` コードではありません。[4625](/ja/blog/detecting-4625-brute-force) の `Status` / `SubStatus` フィールドは NTSTATUS コードです。`0xC000006A` は有効なアカウントに対するパスワード誤り、`0xC0000064` は存在しないユーザー名、`0xC0000234` はロックアウトされたアカウントです。[4769](/ja/blog/event-id-4769-kerberoasting) の `TicketEncryptionType` は Kerberos の etype で、`0x17` は RC4-HMAC、`0x12` は AES256 です。どちらもプロバイダーが存在していても生の 16 進値で表示されます。

## 対処法 1: 表示情報付きでエクスポートする

ソース ホストにまだアクセスできるなら、メッセージと一緒に持ち運べる形でログをエクスポートします。イベント ビューアーでログを右クリックし、**[すべてのイベントを名前を付けて保存]** を選び、`.evtx` を指定して、次のダイアログで表示情報を含める言語を選択します (英語版 Windows では **Display information for these languages**)。イベント ビューアーはファイルの隣に `LocaleMetaData` フォルダーを作成し、言語ごとに `.MTA` ファイルを 1 つ書き出します。コピーするときはこのフォルダーを `.evtx` の隣に置いたままにしてください。解析マシンのイベント ビューアーがこれを利用します。

コマンド ラインでは次のとおりです。

```powershell
wevtutil epl Security C:\ir\Security.evtx
wevtutil al C:\ir\Security.evtx /l:en-US
```

`wevtutil al` (archive-log) は、エクスポート済みファイルにロケール メタデータを追加します。大規模な収集については [稼働中システムからの EVTX 収集](/ja/blog/collecting-evtx-from-live-system) を参照してください。

## 対処法 2: プロバイダーをインストールまたは修復する

自分で管理しているマシンで、自社ソフトウェアのイベントがレンダリングされない場合:

- ソースを所有するアプリケーションを再インストールまたは修復する。
- `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>` の `EventMessageFile` を確認する。パスが存在すること、`%SystemRoot%` を含むなら値の種類が `REG_EXPAND_SZ` であること。
- マニフェスト プロバイダーなら `Get-WinEvent -ListProvider <Name>` を確認する。エラーになる、またはメッセージが列挙されない場合はマニフェストの登録が壊れています (バイナリが所定の場所にあれば `wevtutil im <manifest>.man` で再登録できます)。

## 対処法 3: ソース ホスト上でレンダリングする

`Get-WinEvent` が `Message` プロパティを埋めるのは、プロバイダーがローカルに存在する場合だけです。ソース ホスト (または同じソフトウェアがインストールされたマシン) では次が機能します。

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

手元のワークステーションでは同じコマンドでも `Message` は空になりますが、`.Properties` と `.ToXml()` ではすべての値を取得できます。フィルターのレシピは [Get-WinEvent で EVTX をクエリする](/en/blog/query-evtx-powershell-get-winevent) (英語) を参照してください。

## 対処法 4: たいていメッセージは不要

DFIR において、レンダリングされた文章は便宜的なものにすぎません。表示されるはずの値はすべて `<EventData>` にあります: `TargetUserName`、`LogonType`、`IpAddress`、`Status`、`SubStatus`。イベント ビューアーの **[詳細]** タブ (XML 表示) は、[全般] タブにエラーが出ていてもこれらを表示します。大規模に分析するアナリストはいずれにせよフィールドを直接読みます。[4624](/ja/blog/understanding-event-id-4624) や [ログオン イベント全般](/en/blog/windows-logon-events-explained) もそのように扱うべきです。フィールド名は Windows のバージョンや言語が変わっても安定していますが、レンダリングされた文章はそうではありません。

## ブラウザーでオフラインにイベントを読む

[EVTX パーサー](/ja) は、よく使われる約 60 の DFIR イベントについて読みやすい 1 行の説明を表示するようになりました。対象はログオンと 4625 の失敗、アカウントとグループの変更、Kerberos 4768/4769/4771、NTLM 4776、サービス 7045/4697、スケジュール タスク、Sysmon、PowerShell 4104、RDP です。さらに `%%` コード、NTSTATUS コード (`0xC000006A` パスワード誤り、`0xC0000064` 不明なユーザー)、Kerberos チケットの暗号化タイプ (`0x17` RC4) をその場でデコードします。プロバイダー DLL も Windows も不要で、ファイルはブラウザー内で解析され、アップロードされることはありません。ファイルを開くその他の方法は [EVTX ファイルの開き方](/ja/blog/how-to-open-an-evtx-file) を参照してください。

## チェックリスト

- このエラーは **表示しているマシン** にプロバイダーがないことを意味し、レコードの破損ではない。
- `<EventData>` を [詳細] タブ、`Get-WinEvent` の `.Properties`、またはパーサーで読む。
- `%%` 参照は上の表でデコードし、`Status` / `SubStatus` は NTSTATUS としてデコードする。
- レポートにレンダリング済みの文章が必要なら、ソース ホストで表示情報付き (`LocaleMetaData`) または `wevtutil al` で再エクスポートする。
- 自社ソフトウェアなら `EventMessageFile` を修正するか、マニフェストを再登録する。

---
title: ".evtx ファイルとは何か:Windows イベント ログ形式を解説"
description: ".evtx ファイルはバイナリ形式の Windows イベント ログです。保存場所、内部構造、.evt との違い、そしてインストール不要で開く方法を解説します。"
date: "2026-05-24"
faq:
  - question: ".evtx ファイルとは何ですか?"
    answer: ".evtx ファイルは、Windows Vista で導入されたバイナリ形式の Windows イベント ログです。EventLog サービスが書き込むシステム、セキュリティ、アプリケーションのイベントを保存します。Windows マシンには C:\\Windows\\System32\\winevt\\Logs\\ 配下に数十個の .evtx ファイルがあり、各チャネルごとに 1 ファイルが対応します。"
  - question: ".evtx ファイルは Windows のどこに保存されますか?"
    answer: "既定の保存場所は C:\\Windows\\System32\\winevt\\Logs\\ です。トラフィックの多い 3 つの主要ファイルは Security.evtx、System.evtx、Application.evtx です。アプリケーション単位のチャネルは同じフォルダ内に Microsoft-Windows-Sysmon%4Operational.evtx のような名前で保存されます。"
  - question: ".evtx と .evt の違いは何ですか?"
    answer: ".evt は Windows XP および Server 2003 まで使用されていた旧バイナリ形式です。.evtx は Windows Vista(2007 年)でこれを置き換え、より豊富なイベント メタデータ、大容量ログ、wevtutil や Get-WinEvent による構造化クエリをサポートするチャンク化された BinXML ベースのレイアウトを採用しました。2 つの形式に互換性はありません。"
  - question: ".evtx ファイルはどうやって開きますか?"
    answer: "Windows 標準ツール:イベント ビューア(eventvwr.msc)、コマンド ラインの wevtutil、PowerShell の Get-WinEvent。クロスプラットフォーム:本サイトのブラウザ ベース パーサー(インストール・アップロード不要)、またはコマンド ラインの evtxecmd。すべての選択肢は how-to-open-an-evtx-file の記事を参照してください。"
  - question: ".evtx ファイルは macOS や Linux でも開けますか?"
    answer: "はい。Windows ネイティブ ツールは使えませんが、複数のクロスプラットフォーム パーサーが利用できます:本サイトのブラウザ ベース パーサー(モダン ブラウザのある任意の OS)、python-evtx、Rust の evtx クレート、mono 経由の evtxecmd などです。いずれも Windows ホストを必要としません。"
---

`.evtx` ファイルは、Microsoft が 2007 年に Windows Vista と共に出荷し、旧来の `.evt` 形式を置き換えたバイナリ形式の Windows イベント ログです。OS、ドライバ、サービス、アプリケーションが Windows イベント ログに書き込むイベントは、すべてディスク上の `.evtx` ファイルに格納されます。あらゆる Windows 調査の屋台骨となるファイルです。

## 簡潔な答え

`.evtx` ファイルは Windows EventLog サービスが `C:\Windows\System32\winevt\Logs\` に書き込みます。**チャネル**ごとに 1 ファイル(`Security.evtx`、`System.evtx`、`Application.evtx` のほか、アプリケーション固有のチャネル)が存在します。内部はチャンク化されたバイナリ コンテナで、`BinXML` でエンコードされたレコードが格納されており、プレーン テキストではありません。読み込むにはイベント ビューア、`wevtutil`、`Get-WinEvent`、またはサードパーティ パーサーを使用します。

## .evtx ファイルの保存場所

サポートされるすべての Windows バージョン(Vista から Windows 11 / Server 2025 まで)の標準的な保存場所:

```text
C:\Windows\System32\winevt\Logs\
```

各 `.evtx` ファイルは 1 つのイベント チャネルに対応します。常に存在する既定のファイル:

- `Security.evtx` — ログオン、特権の使用、監査ポリシーの変更。多くのケースでフォレンジック上もっとも価値が高いファイル。
- `System.evtx` — ドライバ、サービス、カーネル レベルのエラー。
- `Application.evtx` — アプリケーション レベルのエラーおよび情報イベント。
- `Setup.evtx` — インストール記録。
- `ForwardedEvents.evtx` — Windows Event Forwarding(WEF)経由で他ホストから収集されたイベント。

アプリケーション単位のチャネルは同じフォルダに保存され、パス区切り文字の代わりに `%4` が使用されます:

- `Microsoft-Windows-Sysmon%4Operational.evtx` — Sysmon のプロセス、ネットワーク、ファイル イベント(インストール時)。
- `Microsoft-Windows-PowerShell%4Operational.evtx` — PowerShell の ScriptBlock とモジュール ロギング。
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` — スケジュールド タスクの作成と実行。
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` — RDP セッションのライフサイクル。

ローテーションされたチャネルは同じフォルダにタイムスタンプ付きのアーカイブ ファイルを生成します(`Security.evtx`、`Archive-Security-2026-05-23-…evtx` のように)。アクティブなファイルは Windows 動作中、EventLog サービスによって開かれた状態で保持されます。

## .evtx ファイルの中身

このファイルはバイナリ コンテナであり、プレーン テキストではありません。4 KB のヘッダ(マジック値 `ElfFile\0`)に続いて、64 KB の**チャンク**列が並びます。各チャンクは独自のヘッダ(`ElfChnk`)、そのチャンク内に現れる XML **テンプレート**のテーブル、そしてテンプレートを ID で参照するレコードのストリームを持ちます。パーサーはレコード単位の値をテンプレートのプレースホルダに代入することで各イベントを再構築します。これが `.evtx` をディスク上で生 XML よりもコンパクトに保つ仕組みです。

デコードされた各レコードは、2 つの部分から成る XML 文書です:

- `<System>` — プロバイダ名、チャネル、Event ID、レベル(1 Critical → 5 Verbose)、コンピュータ名、セキュリティ コンテキスト、UTC の書き込みタイムスタンプ。
- `<EventData>` — プロバイダ固有のパラメータ:ログオンの対象アカウント、プロセス作成時のイメージ パス、監査された書き込みのレジストリ キーなど。

Event ID だけではトリアージには不十分です。フォレンジック上のシグナルは `<EventData>` に存在します。フォーマットの深い仕組み — チャンク、BinXML、テンプレート、ダーティ チャンク復旧 — については [EVTX ファイル形式の内部構造](/ja/blog/evtx-file-format-chunks) を参照してください。

## .evtx と .evt:なぜ形式が変わったのか

XP および Server 2003 まで使用されていた旧 `.evt` 形式には、新形式が解決しようとした 3 つの厳しい制限がありました:

- **固定サイズの文字列。** `.evt` レコードは完全なメッセージではなくメッセージ テーブルへの参照を保持していたため、ソース DLL が欠落したり更新されたりすると描画時の結合が壊れました。
- **構造化クエリの欠如。** フィルタリングするには全レコードを線形に読み、パースする必要がありました。
- **1 ファイルにつき 1 チャネル。** カスタム アプリケーション ログは独自の非標準形式を必要としました。

`.evtx`(Vista、2007 年)は BinXML レコード、任意ネスト可能なチャネル単位ファイル、`wevtutil qe` と `Get-WinEvent -FilterHashtable` による XPath スタイルのフィルタリング、そして部分書き込みに耐えるチャンク化レイアウトを導入しました。トレードオフは互換性の完全な断絶でした — `.evt` と `.evtx` に互換性はなく、モダン Windows で `.evt` を読める唯一の標準ツールはレガシー フラグ付きの `wevtutil` のみで、しかも `.evtx` へのエクスポートに限られます。

## .evtx ファイルの開き方

導入の手間が少ない順に、主要な 5 通りを紹介します:

1. **ブラウザでインストール不要** — 本サイトのトップ ページにあるパーサーへファイルをドロップします。WebAssembly にコンパイルした Rust 製の [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) クレートを Web Worker 内で実行します。マシンから何も外に出ません。フォレンジック VM を立ち上げたくない、その場限りのトリアージに向いています。
2. **イベント ビューア(`eventvwr.msc`)** — Windows 標準の GUI。イベント ビューア → 操作 → 保存されたログを開く… → `.evtx` を選択。閲覧には良いが、大量のフィルタリングには弱い。
3. **`wevtutil` / `Get-WinEvent`** — コマンド ラインと PowerShell。どちらも Windows に同梱。`wevtutil qe path\to\file.evtx /f:text /lf:true` で全レコードをダンプ。`Get-WinEvent -Path` は `Where-Object` にパイプ可能なオブジェクトを返します。
4. **EvtxECmd** — Eric Zimmerman 氏のパーサー。.NET 経由でクロスプラットフォーム、高速、`<EventData>` をすべて平坦化した 1 レコード 1 行の CSV を生成します。
5. **`python-evtx`** — 純 Python 製でスクリプト化が容易。Rust クレートより遅いものの、すでに Python ツール チェーンがある場合に有用です。

各手法の実際に実行するコマンドを含む詳細な手順は、[.evtx ファイルの開き方](/ja/blog/how-to-open-an-evtx-file) を参照してください。

## 実務で .evtx に出会う場面

- **インシデント レスポンス。** 侵害ホストからトリアージの一環として取得。注目すべきチャネルは手がかり次第 — ログオンや特権の悪用なら `Security`、プロセス ツリーなら `Sysmon`、ScriptBlock の内容なら `PowerShell`。
- **コンプライアンス監査。** 監査人は定められた期間の `Security.evtx` を要求し、ログオンとポリシー変更の履歴を検証します。
- **アプリケーションのデバッグ。** `Application.evtx` とベンダー固有チャネルには、アプリケーション自身のログには無いクラッシュやエラーのコンテキストが残ります。
- **脅威ハンティング。** アーカイブされた `.evtx`(またはライブ チャネルを転送している SIEM)に対する長期間ルールが、業務時間外 RDP やサービス アカウントの `LogonType` の変化といった、ゆっくり進行するパターンを捕捉します。

もっとも有用な切り口は Event ID です。実運用の SOC で価値を発揮する厳選リスト — [4624 ログオン成功](/ja/blog/understanding-event-id-4624)、[4625 ログオン失敗](/ja/blog/detecting-4625-brute-force)、[1102 ログの消去](/ja/blog/event-id-1102-cleared-log)、[4104 PowerShell ScriptBlock](/ja/blog/powershell-4104-scriptblock)、[7045 サービスのインストール](/ja/blog/service-creation-event-id-7045)、[Sysmon 1 プロセス作成](/ja/blog/sysmon-event-id-1-process-create) — は [スタート地点となるオリエンテーション](/ja/blog/welcome) を参照してください。

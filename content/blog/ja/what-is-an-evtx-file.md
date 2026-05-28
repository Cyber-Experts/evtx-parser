---
title: ".evtx ファイルとは何か? Windows イベントログ形式の解説"
description: ".evtx ファイルはバイナリの Windows イベントログです。配置場所、中身、.evt との違い、開き方を解説。インストール不要。"
date: "2026-05-24"
faq:
  - question: ".evtx ファイルとは何ですか?"
    answer: ".evtx ファイルは、Windows Vista とともに導入されたバイナリ形式の Windows イベントログです。EventLog サービスが書き込んだシステム、セキュリティ、アプリケーション イベントを格納します。各 Windows マシンでは、C:\\Windows\\System32\\winevt\\Logs\\ の下に、チャネルごとに 1 つずつ、数十の .evtx ファイルが存在します。"
  - question: "Windows 上で .evtx ファイルはどこに保存されますか?"
    answer: "既定の場所は C:\\Windows\\System32\\winevt\\Logs\\ です。トラフィックが多い 3 つのファイルは Security.evtx、System.evtx、Application.evtx です。アプリケーション別チャネルは同じフォルダに Microsoft-Windows-Sysmon%4Operational.evtx のような名前で配置されます。"
  - question: ".evtx と .evt の違いは何ですか?"
    answer: ".evt は XP や Server 2003 まで Windows が使っていたレガシーなバイナリ形式です。.evtx は Windows Vista (2007) でそれを置き換え、より豊富なイベント メタデータ、より大きなログ、wevtutil と Get-WinEvent による構造化クエリをサポートするチャンク化された BinXML ベースのレイアウトを採用しました。両形式に互換性はありません。"
  - question: ".evtx ファイルを開くにはどうしますか?"
    answer: "Windows 標準ツール: Event Viewer (eventvwr.msc)、コマンドラインの wevtutil、PowerShell の Get-WinEvent。クロスプラットフォーム: 本サイトのブラウザ ベース パーサー(インストール不要、アップロードなし)、またはコマンドラインの evtxecmd。すべての選択肢については how-to-open-an-evtx-file の記事を参照してください。"
  - question: "macOS や Linux で .evtx ファイルを開けますか?"
    answer: "はい。Windows 標準ツールは動作しませんが、いくつかのクロスプラットフォーム パーサーが動作します。本サイトのブラウザ ベース パーサー(モダン ブラウザがあるどの OS でも)、python-evtx、Rust の evtx クレート、.NET 経由の evtxecmd。どれも Windows ホストを必要としません。"
---

`.evtx` ファイルは、Microsoft が 2007 年に Vista で旧来の `.evt` を置き換えるためにリリースしたバイナリの Windows イベントログ形式です。OS、ドライバー、サービス、アプリケーションが Windows イベントログに書き込むあらゆるイベントは、ディスク上の `.evtx` ファイルに記録されます。これは Windows 調査すべての背骨です。Windows で DFIR をやるなら、他のどのアーティファクト クラスよりも、このファイルの中で過ごす時間の方が長くなるはずです。

## 端的に言うと

`.evtx` ファイルは Windows EventLog サービスが `C:\Windows\System32\winevt\Logs\` に書き込みます。**チャネル**ごとに 1 ファイルです (`Security.evtx`、`System.evtx`、`Application.evtx`、加えてアプリケーション別チャネル)。内部的には、各ファイルは `BinXML` でエンコードされたレコードのチャンク化バイナリ コンテナです。プレーン テキストではありません。Event Viewer、`wevtutil`、`Get-WinEvent`、またはサードパーティ パーサーで読みます。

## .evtx ファイルの場所

サポートされているすべての Windows バージョン (Vista から Windows 11 と Server 2025 まで) の標準的な場所:

```text
C:\Windows\System32\winevt\Logs\
```

各 `.evtx` ファイルは 1 つのイベント チャネルに対応します。デフォルト:

- `Security.evtx`。ログオン、特権利用、監査ポリシー変更。ほとんどの事案でフォレンジック価値が最も高い。
- `System.evtx`。ドライバー、サービス、カーネル レベルのエラー。
- `Application.evtx`。アプリケーション レベルのエラーと情報イベント。
- `Setup.evtx`。インストール記録。
- `ForwardedEvents.evtx`。Windows Event Forwarding (WEF) 経由で他のホストから収集されたイベント。

アプリケーション別チャネルは同じフォルダに、パス区切り記号の代わりに `%4` を使った名前で格納されます。

- `Microsoft-Windows-Sysmon%4Operational.evtx`。Sysmon のプロセス、ネットワーク、ファイル イベント (インストール時)。
- `Microsoft-Windows-PowerShell%4Operational.evtx`。PowerShell scriptblock とモジュール ロギング。
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`。スケジュールド タスクの作成と実行。
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`。RDP セッションのライフサイクル。

ローテーションされたチャネルは、同じフォルダにタイムスタンプ付きアーカイブ ファイルを生成します (`Security.evtx`、`Archive-Security-2026-05-23-...evtx`)。Windows が稼働している間、アクティブ ファイルは EventLog サービスが開いたままにします。これが、[ライブ ホストからこれらのファイルを取り出す方法](/ja/blog/collecting-evtx-from-live-system) という記事が存在する理由そのものです。

## .evtx ファイルの中身

ファイルはバイナリ コンテナで、プレーン テキストではありません。4 KB のヘッダー(マジック `ElfFile\0`)に続いて、64 KB の**チャンク**が連なります。各チャンクは独自のヘッダー (`ElfChnk`)、その中で出現する XML **テンプレート**のテーブル、そしてそれらを ID で参照するレコードのストリームを持ちます。パーサーは、レコード レベルの値をテンプレートのプレースホルダーに代入することで各イベントを再構築します。これが `.evtx` をディスク上で文字どおりの XML よりコンパクトにしている理由です。

デコードすると、各レコードは 2 つの半分から成る XML ドキュメントになります。

- `<System>`。プロバイダー名、チャネル、Event ID、レベル (1 重大から 5 詳細)、コンピューター名、セキュリティ コンテキスト、UTC 書き込みタイムスタンプ。
- `<EventData>`。プロバイダー固有のパラメータ。ログオンの対象アカウント、プロセス作成のイメージ パス、監査された書き込みのレジストリ キー、などなど。

Event ID 単体ではトリアージに足りないことが多いです。フォレンジックの信号は `<EventData>` に宿ります。形式の細部 (チャンク、BinXML、テンプレート、ダーティ チャンクの復旧) については、[チャンク レベルの詳細](/ja/blog/evtx-file-format-chunks) を参照してください。

## .evtx 対 .evt: 形式が変わった理由

XP と Server 2003 まで Windows が使っていたレガシーな `.evt` 形式には、新形式が解決するために設計された 3 つの厳しい制約がありました。

- **固定長の文字列。** `.evt` レコードはメッセージ全体ではなくメッセージ テーブルへの参照を持っていました。ソース DLL が欠落していたりアップグレードされていたりすると、レンダリング時のジョインが壊れました。
- **構造化クエリがない。** フィルタリングするには、すべてのレコードを線形に読んで解析する必要がありました。
- **ファイルあたり 1 チャネル。** カスタム アプリケーション ログには独自の非標準形式が必要でした。

`.evtx` (Vista、2007) では、BinXML レコード、任意の階層を持つチャネル別ファイル、`wevtutil qe` と `Get-WinEvent -FilterHashtable` による XPath 形式のフィルタリング、そして部分書き込みに耐えるチャンク化レイアウトが導入されました。代償は完全な互換性の断絶でした。`.evt` と `.evtx` は互換性がなく、最新の Windows で `.evt` を読める標準ツールは、レガシー フラグを指定した `wevtutil` のみです (しかも `.evtx` へのエクスポート用途のみ)。

## .evtx ファイルの開き方

5 つの一般的な経路を、おおよそ手間の少ない順に紹介します。

1. **ブラウザで、インストール不要。** 本サイトのトップ ページのパーサーにファイルをドロップしてください。Web Worker 内で WebAssembly にコンパイルされた Rust の [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) クレートを実行します。何もマシンから出ません。フォレンジック VM を立ち上げたくない即席トリアージに最適です。
2. **Event Viewer (`eventvwr.msc`)**。Windows の組み込み GUI。**操作 / 保存されたログを開く / .evtx を選択**。閲覧には向いていますが、スケールでのフィルタリングには弱い。
3. **`wevtutil` / `Get-WinEvent`**。コマンドラインと PowerShell、どちらも Windows に付属しています。`wevtutil qe path\to\file.evtx /f:text /lf:true` ですべてのレコードをダンプします。`Get-WinEvent -Path` はオブジェクトを返すので `Where-Object` にパイプできます。
4. **EvtxECmd**。Eric Zimmerman のパーサー。.NET でクロスプラットフォーム、高速、レコードごとに 1 行の CSV を生成し、`<EventData>` をフラット化します。
5. **`python-evtx`**。純 Python、スクリプト化が容易。Rust クレートより遅いですが、すでに Python ツール チェーンを使っているなら有用です。

それぞれの完全なウォークスルーと実際のコマンドについては、[.evtx ファイルの開き方](/ja/blog/how-to-open-an-evtx-file) を参照してください。

## .evtx に出会う場面

- **インシデント対応。** トリアージの一環として侵害されたホストから取り出します。関心のあるチャネルは追跡対象によって異なります。ログオンと特権濫用なら `Security`、プロセス ツリーなら `Sysmon`、scriptblock 内容なら `PowerShell`。実行の裏付けには [registry](https://www.registryparser.com)、[MFT](https://www.mftparser.com)、[USN journal](https://www.usnparser.com)、[AmCache](https://www.amcacheparser.com)、[prefetch](https://www.prefetchparser.com) と組み合わせてください。
- **コンプライアンス監査。** 監査人はログオンとポリシー変更の履歴を確認するため、定義された期間の `Security.evtx` を要求します。
- **アプリケーション デバッグ。** `Application.evtx` とベンダー別チャネルには、アプリ自体のログには現れないクラッシュやエラー コンテキストが含まれていることが多いです。
- **脅威ハンティング。** アーカイブされた `.evtx` (またはライブ チャネルを転送する SIEM) に対する長期傾向のルールが、深夜帯の RDP やサービス アカウントの `LogonType` ドリフトのような長期的なパターンを捉えます。

最も有用な軸は Event ID です。実際の SOC で本領を発揮する短いリスト ([4624](/ja/blog/understanding-event-id-4624)、[4625](/ja/blog/detecting-4625-brute-force)、[1102](/ja/blog/event-id-1102-cleared-log)、[4104](/ja/blog/powershell-4104-scriptblock)、[7045](/ja/blog/service-creation-event-id-7045)、[Sysmon 1](/ja/blog/sysmon-event-id-1-process-create)) については、[ここから始めるオリエンテーション](/ja/blog/welcome) を参照してください。

## 参考資料

- [Microsoft ドキュメント: Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [libevtx EVTX 形式仕様](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc)
- [omerbenamram/evtx (Rust パーサー)](https://github.com/omerbenamram/evtx)

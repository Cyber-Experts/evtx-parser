---
title: ".evtx ファイルの開き方 (5 つの方法、インストール不要)"
description: "Windows .evtx ファイルを開く 5 つの方法: ブラウザ、Event Viewer、wevtutil、EvtxECmd、python-evtx。ホスト OS と許容できる手間で選んでください。"
date: "2026-05-24"
howto:
  name: ".evtx ファイルの開き方"
  steps:
    - name: "ブラウザで開く (インストール不要)"
      text: "EVTX パーサーのホーム ページに行き、.evtx ファイルをアップロード ゾーンにドロップします。ファイルは WebAssembly にコンパイルされた Rust の EVTX パーサーを使用して Web Worker でローカルに解析されます。アップロードはありません。Windows、macOS、Linux で動作します。"
    - name: "Event Viewer で開く (Windows のみ)"
      text: "eventvwr.msc を起動、Action から Open Saved Log を選択、.evtx ファイルを参照、ビューに名前を付けて OK をクリック。1 つのチャネルの閲覧には良いですが、数千レコードをまたぐフィルタリングには弱い。"
    - name: "wevtutil または Get-WinEvent でダンプ (Windows コマンドライン)"
      text: "wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt を実行して、すべてのレコードをテキストとしてエクスポート。PowerShell からは、Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 でさらにパイプできるパース済みオブジェクトを返します。"
    - name: "EvtxECmd でパース (クロスプラットフォーム CLI)"
      text: "Eric Zimmerman のツールから EvtxECmd をダウンロードし、EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv を実行して、すべてのレコード (すべての EventData フィールドを含む) をイベントあたり 1 CSV 行にフラット化。"
    - name: "python-evtx でスクリプト化 (クロスプラットフォーム Python)"
      text: "pip install python-evtx を実行してから、python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml を実行して、すべてのレコードを stdout に XML として取得。Rust パーサーより遅いですが、パイプラインや Jupyter ノートブックに組み込みやすい。"
---

`.evtx` ファイルはバイナリの Windows イベント ログ形式です ([中身](/ja/blog/what-is-an-evtx-file))。テキスト エディタでは読めません。チャンク化バイナリ コンテナ内の BinXML です。「ファイルをドロップして完了」から「Python パイプラインに配線する」まで、おおむね手間の少ない順に、5 つの方法があらゆる現実的なケースをカバーします。

## 方法 1: ブラウザで開く、インストール不要

任意の OS で最速の経路。[本サイトのホーム ページ](/ja) のパーサーに `.evtx` をドロップしてください。ファイルはブラウザのメモリに読み込まれ、WebAssembly にコンパイルされた [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) クレートを実行する Web Worker によってローカルに解析されます。何もマシンから離れません。ファイルをドロップする前にネットワークから切断して確認してください。

デスクトップ ツールが生成するのと同じレコード レベル ビューが得られます: フィルタ可能なタイムライン、テーブルにフラット化された完全な `<EventData>`、ワンクリックで完全な XML、フィルタ済み セットの CSV/JSON エクスポート。何もインストールしたくない、アップロードしたくない、自分のマシンではないときの即席トリアージに最適。

制約。ブラウザのメモリ上限により、約 500 MB を超えるファイルは遅くなります。マルチ ギガバイトのアーカイブ ログには、ネイティブ ツールに降りてください。

## 方法 2: Event Viewer、Windows のみ、組み込み

すべての Windows インストールには Event Viewer が付属しています。`eventvwr.msc` を起動、**操作 / 保存されたログを開く** で `.evtx` を選択。Event Viewer は現在のビューにファイルをインポートするか尋ねます。承諾すれば、ライブ チャネルのように閲覧できます。

```text
操作 -> 保存されたログを開く -> 参照 -> .evtx を選択 -> OK
```

1 つのファイルの閲覧、1 つのレコードのフレンドリ フォーマット メッセージを見る、XML ビューをコピー アンド ペーストするのには良い。数千レコードのフィルタリング (UI が遅くなる)、一括エクスポート、スクリプト化するクエリの実行には弱い。また、ダーティな末尾チャンクに最も厳格: 他のツールが受け入れるファイルを拒否します。

## 方法 3: wevtutil と Get-WinEvent、Windows コマンドライン

`wevtutil` はログ管理用の Windows 組み込みです。`Get-WinEvent` は PowerShell 対応版です。両方ともライブ チャネルだけでなく、保存された `.evtx` ファイルにも動作します。

保存された `.evtx` のすべてのレコードをテキストにダンプ:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

XPath でフィルタ。過去 24 時間のすべての 4624:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

同じ意図で型付きオブジェクトを返す PowerShell:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

スクリプト抽出、スケジュールされたジョブ、外科的フィルタリングに良い。トレードオフは冗長性。XML に対する XPath は正確ですが、親しみやすくはありません。

## 方法 4: EvtxECmd、DFIR 標準

[Eric Zimmerman の `EvtxECmd`](https://ericzimmerman.github.io/) は、ほとんどの IR 実務家がデフォルトで使うパーサーです。Windows ネイティブで動作し、.NET 経由で macOS / Linux でも動作します。`wevtutil` より速くパースし、すべての `<EventData>` フィールドを CSV カラムにフラット化します。レコードあたり 1 行。

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

既知のイベント フィールドをフレンドリ カラムにデコードするマップで、`winevt\Logs\` フォルダ全体を 1 パスで:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

マルチファイル コレクションの一括パース、SIEM やノートブックへのインポート、クロスプラットフォーム アナリスト ワークフローに最適。EvtxECmd はほぼすべての「これをオフラインでパース」タスクに対する正解です。KAPE の `EventLogs` ターゲットと組み合わせれば、1 コマンドのエンゲージメントになります。

## 方法 5: python-evtx、パイプラインにスクリプト化

ファイルが Python パイプラインを供給する必要があるとき、[`python-evtx`](https://github.com/williballenthin/python-evtx) は純 Python パーサーです。

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

ノートブックまたはスクリプト内:

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Rust クレートより遅い (バイナリ チャンクに対する解釈 Python) が、すでに Python ツール チェーン内にいるときの正解: Jupyter フォレンジック ノートブック、脅威ハンティング ジョブ、カスタム エンリッチメント、同じケースからの EVTX データを [registry](https://www.registryparser.com)、[MFT](https://www.mftparser.com)、[USN](https://www.usnparser.com)、または [prefetch](https://www.prefetchparser.com) アーティファクトに結合。

## どの方法をいつ使うか

- ファイルを見たいだけ: [ホーム ページのパーサー](/ja) にドロップ。最速、インストール ゼロ。
- 管理者権限があり、ファイルが小さい Windows エンドポイント: Event Viewer。
- スクリプト化された 1 回限りの抽出: `wevtutil` または `Get-WinEvent`。
- マルチ チャネル コレクションでの本格的な DFIR: EvtxECmd。
- Python でパイプライン構築: `python-evtx`。

## 一般的なエラーと読み方

- Event Viewer での「ファイルが有効ではないようです」は、ほぼ常に末尾チャンクがダーティ (EventLog サービスがまだ書き込んでいる間にファイルがコピーされた) を意味します。多くのパーサーはこれを扱います。両方ともダーティ チャンクを警告として報告して続行する[ブラウザ パーサー](/ja) または `EvtxECmd` を試してください。
- `winevt\Logs\` 内のファイルに対する `wevtutil` からの「アクセスが拒否されました」は、EventLog サービスが排他ロックを保持しています。4 つの標準的な回避方法については [ライブ システムからの .evtx 収集](/ja/blog/collecting-evtx-from-live-system) を参照。
- 保存されたログに対する `Get-WinEvent` からの空出力。`-LogName` ではなく `-Path` でファイルを渡してください。`-LogName` はライブ チャネルのみを読みます。
- PowerShell `Get-WinEvent` が「指定された選択基準に一致するイベントは見つかりませんでした」と言う。`-FilterHashtable` キーは一部のプロパティで大文字小文字を区別します。ファイルがパースされることを確認するため、まずフィルタなしで試してください。

`.evtx` の実際の内容と、なぜ形式がこう見えるかの背景については、[チャンク レベルの詳細](/ja/blog/evtx-file-format-chunks) を参照してください。

## 参考資料

- [Eric Zimmerman のツール](https://ericzimmerman.github.io/)
- [omerbenamram/evtx (Rust)](https://github.com/omerbenamram/evtx)
- [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx)

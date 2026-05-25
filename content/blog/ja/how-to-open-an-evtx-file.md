---
title: ".evtx ファイルの開き方(5 つの方法、インストール不要)"
description: "Windows の .evtx ファイルを開く 5 つの方法 — ブラウザ、イベント ビューア、wevtutil、EvtxECmd、python-evtx。ホスト OS と許容できる手間に応じて選んでください。"
date: "2026-05-24"
howto:
  name: ".evtx ファイルの開き方"
  steps:
    - name: "ブラウザで開く(インストール不要)"
      text: "EVTX パーサーのトップ ページに移動し、.evtx ファイルをアップロード エリアにドロップします。ファイルは WebAssembly にコンパイルされた Rust 製 EVTX パーサーを使い、Web Worker 内でローカルに解析されます。アップロードは行われません — 検証したい場合はネットワークを切断してください。Windows、macOS、Linux で動作します。"
    - name: "イベント ビューアで開く(Windows のみ)"
      text: "eventvwr.msc を起動し、操作 → 保存されたログを開く… を選び、.evtx ファイルを参照してビュー名を付け、OK をクリックします。1 つのチャネルを閲覧するのには向いていますが、数千レコードを跨ぐフィルタリングには弱いです。"
    - name: "wevtutil または Get-WinEvent でダンプする(Windows コマンド ライン)"
      text: "wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt を実行して全レコードをテキストとしてエクスポートします。PowerShell からは Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 でパース済みオブジェクトが返り、さらにパイプ処理できます。"
    - name: "EvtxECmd でパースする(クロスプラットフォーム CLI)"
      text: "Eric Zimmerman のツールから EvtxECmd をダウンロードし、EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv を実行して、全 EventData フィールドを含む全レコードをイベント 1 件 1 行の CSV に平坦化します。Windows ではそのまま動作し、macOS / Linux では .NET 経由で動作します。"
    - name: "python-evtx でスクリプト化する(クロスプラットフォーム Python)"
      text: "pip install python-evtx を実行し、続いて python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml を実行すると、全レコードが XML として標準出力に得られます。Rust パーサーより遅いものの、パイプラインや Jupyter ノートブックに組み込みやすいです。"
---

`.evtx` ファイルは、バイナリ形式の Windows イベント ログです([中身については →](/ja/blog/what-is-an-evtx-file))。テキスト エディタでは読めません — チャンク化されたバイナリ コンテナの中に BinXML が格納されているためです。以下では、現実的なあらゆるケースをカバーする 5 つの方法を、「ドロップするだけで完了」から「Python パイプラインへ組み込む」まで、手間の少ない順に紹介します。

## 方法 1 — ブラウザで開く(インストール不要)

どの OS でももっとも速い手順:本サイトの[トップ ページ](/ja)にあるパーサーへ `.evtx` をドロップします。ファイルはブラウザのメモリに読み込まれ、WebAssembly にコンパイルされた [Rust 製 `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) クレートを実行する Web Worker でローカルに解析されます。マシンから何も外に出ません — ドロップ前にネットワークを切断することで確認できます。

デスクトップ ツールと同等のレコード単位ビューが得られます:フィルタリング可能なタイムライン、テーブルに平坦化された完全な `<EventData>`、ワンクリックで表示できる全 XML、そしてフィルタ結果の CSV / JSON エクスポートです。何もインストールしたくない、何もアップロードしたくない、または自分のマシンではない端末で作業している場合の、その場限りのトリアージに最適です。

**制約。** ブラウザのメモリ上限により、約 500 MB を超えるファイルは動作が遅くなります。マルチ ギガバイトのアーカイブ ログには、ネイティブ ツールに切り替えてください。

## 方法 2 — イベント ビューア(Windows のみ、標準搭載)

すべての Windows インストールにはイベント ビューアが同梱されています。`eventvwr.msc` で起動し、**操作 → 保存されたログを開く…** から `.evtx` を選択します。イベント ビューアは現在のビューへのインポートを提案しますので、承諾するとライブ チャネルと同様に閲覧できます。

```text
Action → Open Saved Log… → Browse → select .evtx → OK
```

向いている用途:単一ファイルの閲覧、レコード単位のフレンドリーに整形されたメッセージの確認、XML ビューのコピー&ペースト。向いていない用途:数千レコードのフィルタリング(UI が重くなる)、一括エクスポート、スクリプト化したいクエリの実行。

## 方法 3 — wevtutil / Get-WinEvent(Windows コマンド ライン)

`wevtutil` はログ管理用の Windows 標準コマンドで、`Get-WinEvent` はその PowerShell 版です。どちらもライブ チャネルだけでなく、保存された `.evtx` ファイルに対しても動作します。

保存された `.evtx` から全レコードをテキストにダンプします:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

XPath でフィルタリング(ここでは過去 24 時間の全 4624):

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

同じ意図を PowerShell で記述しつつ、型付きオブジェクトを返す例:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

向いている用途:スクリプト化された抽出、スケジュール ジョブ、精密なフィルタリング。トレードオフは冗長性 — XML に対する XPath は正確ですが親しみやすくはありません。

## 方法 4 — EvtxECmd(クロスプラットフォーム CLI、DFIR の定番)

[Eric Zimmerman 氏の `EvtxECmd`](https://ericzimmerman.github.io/) は、多くの IR 実務者がデフォルトとするパーサーです。Windows ではネイティブに、macOS / Linux では .NET 上で動作し、`wevtutil` より高速に解析でき、`<EventData>` の全フィールドを CSV カラムへ平坦化します。1 レコード 1 行です。

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

`winevt\Logs\` フォルダ全体を 1 パスで処理し、既知のイベント フィールドをフレンドリーなカラムへデコードするマップを使う場合:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

向いている用途:複数ファイル収集物の一括解析、SIEM やノートブックへの取り込み、クロスプラットフォームでのアナリスト ワークフロー。EvtxECmd はほぼすべての「オフライン解析」タスクに対する正解です。

## 方法 5 — python-evtx(パイプラインに組み込む)

ファイルを Python パイプラインに供給する必要がある場合、[`python-evtx`](https://github.com/williballenthin/python-evtx) が純 Python のパーサーです。

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

ノートブックやスクリプトでは:

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Rust クレートよりは遅い(インタープリタ実行の Python がバイナリ チャンクを処理する)ものの、Python ツール チェーンの中にいる場合は正解です — Jupyter フォレンジック ノートブック、脅威ハンティング ジョブ、カスタム エンリッチメントなど。

## どの方法をいつ使うか

- **ファイルをただ見たい**:[トップ ページのパーサー](/ja)にドロップ。最速、インストール ゼロ。
- **Windows エンドポイントで管理者権限を持っており、ファイルが小さい**:イベント ビューア。
- **その場限りの抽出をスクリプト化したい**:`wevtutil` または `Get-WinEvent`。
- **複数チャネル収集物に対して本格的な DFIR を行う**:EvtxECmd。
- **Python でパイプラインを構築している**:`python-evtx`。

## よくあるエラーの読み方

- **イベント ビューアの「ファイルが有効ではないようです」** は通常、末尾のチャンクがダーティ(EventLog サービスが書き込み中にファイルがコピーされた)であることを意味します。ほとんどのパーサーはこれを処理できます — [ブラウザ パーサー](/ja) または `EvtxECmd` を試してください。どちらもダーティ チャンクを警告として報告し、処理を続行します。
- **`winevt\Logs\` 配下のファイルに対する `wevtutil` の「アクセスが拒否されました」** は、EventLog サービスが排他ロックを保持していることが原因です。これを回避する 4 通りの標準的方法については、[稼働中のシステムから .evtx を収集する](/ja/blog/collecting-evtx-from-live-system) を参照してください。
- **保存されたログに対する `Get-WinEvent` の出力が空**:ファイルは `-LogName` ではなく `-Path` で指定してください。`-LogName` はライブ チャネルしか読みません。
- **PowerShell の `Get-WinEvent` が「指定した選択条件に一致するイベントは見つかりませんでした」と言う** — `-FilterHashtable` のキーは、一部のプロパティでは大文字小文字を区別します。まずはフィルタなしで実行し、ファイルが正しくパースできることを確認してください。

`.evtx` の内部に実際に何があるのか、なぜ形式がこのようになっているのかの背景は、[.evtx ファイルとは何か?](/ja/blog/what-is-an-evtx-file) を参照してください。

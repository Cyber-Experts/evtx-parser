---
title: "EVTX ファイル形式の解読"
description: "EVTX バイナリ形式の実務ツアー: ファイル ヘッダー、ELFCHNK チャンク、BinXML テンプレート、置換配列、そしてこれをパースするのが見た目より難しい理由。"
date: "2026-05-27"
tags:
  - evtx
  - file-format
  - binxml
  - dfir
  - reverse-engineering
author: "Florian Amette"
---

古い EVT 形式は、16 進エディタと忍耐があればほぼ読めました。EVTX はそうではありません。Microsoft は Vista で書き込みスループットとマシン消費のために設計されたものに置き換え、副作用は、EVTX ファイルを読みたい誰もが Andreas Schuster のリバース エンジニアリング ノート数百ページを再実装することになる、ということです。形式は `[MS-EVEN6]` でプロトコル層のみ文書化されています。ディスク上の構造は自分で見つけるか、`libevtx` から借りる必要があります。

この記事は、私が始めたときに欲しかったその版です。

## ファイル ヘッダー、簡潔に

すべての EVTX ファイルはオフセット 0 のマジック `ElfFile\0` で 4096 バイトのファイル ヘッダーから開きます。その後、トリアージ中に実際に気にすべきフィールド:

- `FirstChunkNumber` と `LastChunkNumber` — チャンク インデックス、バイト オフセットではない。
- `NextRecordIdentifier` — 次に書かれる RecordID。切り詰めを発見するのに有用。
- `HeaderSize` — ほぼ常に 128、残りの 4096 バイトはゼロ パディング。
- `MinorVersion` / `MajorVersion` — `3.1` は最新の Windows がすべて書き込むバージョン。
- `FileFlags` — bit 0 セットはファイルが dirty (きれいに閉じられなかった)、bit 1 は「フル」でロール中。両方ともフォレンジック解釈に重要。
- ヘッダーの最初の 120 バイトに対する CRC32。CRC を無視するツールは破損ヘッダーを喜んでパースし、強制するツールはあなたがまだレコードを復元できるファイルを拒否します。あなたのがどちらか知ってください。

ヘッダーの後、65,536 バイトのチャンクのシーケンスを得ます。常に 64 KB、常に整列。これは Windows が原子的に書く単位であり、あなたがカービングする単位です。

## ELFCHNK: チャンク ヘッダー

各チャンクはチャンク境界の `ElfChnk\0` で始まります。ヘッダーは 512 バイトで、パースを可能にするフィールドを運びます:

- `FirstEventRecordNumber` と `LastEventRecordNumber` — このチャンクがカバーする RecordID 範囲。
- `FirstEventRecordIdentifier` と `LastEventRecordIdentifier` — 同じこと、レガシーのために保持。
- `FirstEventRecordOffset` — このチャンク内で最初のレコードのバイトが始まる場所。
- `LastEventRecordOffset` — 最後のレコードが始まる場所。これが populated チャンクの末尾を超えていれば、チャンクは部分的にしか書かれていない。ライターがクラッシュしました。
- `StringTable` と `TemplateTable`、両方ともチャンクの BinXML ペイロードを指す FNV スタイル ハッシュをキーとするハッシュ テーブル。
- 2 つの CRC: 1 つはヘッダー、1 つはレコード領域。

文字列とテンプレート テーブルが人を躓かせる部分です。テンプレートと文字列は*チャンクごとに 1 度*格納され、チャンク内のオフセットで参照されます。これは、レコードを孤立して意味のあるパースをすることはできないということです。レコードの XML をレンダリングするには、そのテーブルが解決された包含チャンクが必要です。チャンクなしでレコードをカービングすると、代入先のテンプレートのない置換配列が得られます。

`NumLogRecords` は `LastEventRecordNumber - FirstEventRecordNumber + 1` として暗黙に存在します。一部の初期ドキュメントはこのフィールドを名前で呼び出していました。現代のパーサーは計算します。

## EventRecord エンコーディング

チャンク ヘッダーの後、チャンクが満杯になるか残りがゼロ化されるまで、レコードが背中合わせに続きます。各レコードはマジック `2a 2a 00 00` (生ディスクからのシグネチャ カービングを可能にする — 別記事で詳述) で始まり、続いて:

- `Size` — 末尾の Size 繰り返しを含む総レコード長。
- `EventRecordIdentifier` — 単調増加する RecordID。
- `WriteTime` — Windows FILETIME、1601-01-01 UTC からの 100-ns ティック。
- BinXML ペイロード。
- `Size` 再び、リーダーがレコードを後ろ向きに歩けるよう末尾に繰り返される。

BinXML ペイロードが本当の作業が始まる場所です。

## BinXML とテンプレート/置換モデル

BinXML は XML をバイナリ オペコードとしてエンコードするトークン ストリームです。重要なオペコード:

- `0x00` end-of-stream。
- `0x01` open start tag (属性付き)。
- `0x02` close start tag。
- `0x03` close empty tag。
- `0x04` end element。
- `0x05` value、`ValueType` と値バイトが続く。
- `0x06` attribute。
- `0x0c` template instance。
- `0x0d` normal substitution。
- `0x0e` conditional substitution。
- `0x0f` start of stream (3 バイトのプリアンブル付き)。

Windows イベント ログ ライターは、イベントに対して生 XML を出力することはほぼありません。*テンプレート インスタンス* (`0x0c`) を出力し、テンプレート定義 (ID でチャンクごとに 1 度格納) を参照し、そのテンプレートの変数値を含む*置換配列*を提供します。単一の人間可読 XML レコードをレンダリングするには:

1. テンプレート ID とオフセットでチャンクのテンプレート テーブル内のテンプレートを特定。
2. テンプレートの BinXML を歩き、番号付き置換プレースホルダを持つスケルトンとして扱う。
3. 各プレースホルダについて、置換配列内の対応するエントリを検索し、プレースホルダの宣言された型と型チェックし、インライン化。

置換配列には型付きエントリがあります: UInt32、UInt64、Boolean、GUID、FILETIME、SID、HexInt32、HexInt64、BinXML、EvtHandle、EvtXml、加えて UTF-16LE インラインまたはオフセット参照の文字列、加えて上記のいずれかの配列。型 0x21 は「BinXML」で、置換自体がネストされた BinXML ストリームであることを意味し、パーサーは再帰する必要があります。素朴な実装が転ぶ場所です。

フラグを立てる価値のある 2 つの落とし穴:

- テンプレートは、同じチャンク内の*他*のレコードからオフセットで参照できます。インライン宣言を見たときだけテンプレートを解決するパーサーを構築すると、ID だけで先のテンプレートを参照するレコードを見落とします。
- 「conditional substitution」型 (`0x0e`) は: 値が非 null なら代入、そうでなければ親要素を省略、を意味します。この区別をスキップすると、見た目はよいけれど、実際のログでは何もないところに空要素を持つ XML を生成します。

## EVT のパースより難しい理由

EVT は固定形状レコードのフラット ファイルでした。文字列はインラインで格納されました。午後にパーサーを書けました。

EVTX はページ化、書き込み最適化、自己重複排除形式です。同じ文字列 ("Microsoft-Windows-Security-Auditing") はチャンクごとに 1 度格納され、それを使う各レコードから参照されます。同じ XML スケルトン ("4624 イベント") はチャンクごとに 1 度テンプレートとして格納され、そのチャンク内のすべての 4624 レコードはそれに対する置換配列です。クロス レコード状態が重要です。クロス チャンク状態は重要ではなく、それが救いです: チャンクを失うとそのレコードを失いますが、ファイルの残りは復元可能です。

この重複排除が EVTX を忙しいホストで保持できるほど小さくしているもので、素朴なパーサーが間違える理由でもあります。各レコードの `Provider` フィールドが "Unknown" と言う「パース済み」EVTX を見たことがあれば、文字列テーブルを解決しなかったパーサーを見たことがあります。

## 実際に動くツール

- `python-evtx` (Willi Ballenthin) — 遅い、純 Python だが、最もきれいなリファレンス実装。独自を書く前にそのソースを読んでください。
- Omer Ben-Amram の `evtx` Rust クレートからの `evtx_dump` — 高速、堅牢、コマンドライン ダンプのデフォルト。あらゆるものにパイプできる JSONL 出力。
- `libevtx` と `evtxtools` (Joachim Metz) — C ライブラリ、形式の正準リファレンス。Python バインディング (`pyevtx`) は一部のワークロードで `python-evtx` より遅いですが、エッジ ケースの扱いは良いです。
- Eric Zimmerman の `EvtxECmd` — .NET、マップ システムにより IR フィールドワークのベスト オブ クラス。マップは YAML ファイルで、EventData の置換を名前付きカラムにフラット化します。grep とタイムライン作業に欲しいものです。`Timeline Explorer` と組み合わせてください。
- [本サイトのパーサー](https://www.evtxparser.com) — ブラウザ ベース、規制データをベンダーにアップロードしたくない、または作業しているボックスにキットがないときに有用。

ゼロからパーサーを書くなら (やめてください、しかしどうしても必要なら)、検証する公開テスト コーパスは、[SANS DFIR poster](https://github.com/forensicmatt/EVTX-ETW-Resources) repo と Yamato Security の `hayabusa` サンプル ログからの公開 EVTX サンプルです。最初のパスでコードが間違える不正形式チャンクと部分レコードのケースをカバーしています。

もう 1 つ言う価値: 形式は他の Windows アーティファクトと共有されます。同じ FILETIME エンコーディングが [registry](https://www.registryparser.com)、[MFT](https://www.mftparser.com) `$STANDARD_INFORMATION` タイムスタンプ、[Prefetch](https://www.prefetchparser.com) ヘッダーに現れます。頭で FILETIME を読めるようになると、多くの Windows フォレンジックが静かになります。

## 参考資料

- Andreas Schuster の元の [「Introducing the Microsoft Vista Event Log File Format」](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf) (DFRWS 2007)。それ以降のすべてが引用するリバース エンジニアリング論文。
- Joachim Metz の [libevtx 形式仕様](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc)。完全リファレンスに最も近いもの。
- Willi Ballenthin の [python-evtx ソース](https://github.com/williballenthin/python-evtx)。BinXML ノード階層は `Evtx/Nodes.py` を読んでください。
- Omer Ben-Amram の [evtx Rust クレート](https://github.com/omerbenamram/evtx)。多くの現代ツーリングが乗っている高速パス。

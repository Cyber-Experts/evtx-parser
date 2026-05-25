---
title: "稼働中の Windows システムから .evtx ログを収集する方法（4 つの手段）"
description: "稼働中の Windows ホストから .evtx を取り出す 4 つの方法 — wevtutil、FTK Imager、KAPE、生の NTFS 読み取り — それぞれの証拠保全上のトレードオフと、実際に叩くコマンド。"
date: "2026-05-17"
howto:
  name: "稼働中の Windows システムから .evtx ログを収集する方法"
  steps:
    - name: "wevtutil でエクスポート"
      text: "管理者権限で wevtutil epl Security C:\\triage\\Security.evtx を実行し、稼働中の Security チャネルのポータブルコピーを生のファイルに触れずに固めて取り出します。"
    - name: "FTK Imager で取得"
      text: "FTK Imager を開き、Add Evidence Item → Physical or Logical Drive で \\Windows\\System32\\winevt\\Logs\\ に移動し、チャネルファイル（アーカイブ済みの *.evtx を含む）を選択して Export Files。FTK は NTFS を直接読むため、EventLog サービスのファイルロックを回避できます。"
    - name: "KAPE で一括収集"
      text: "kape.exe --tsource C: --target EventLogs --tdest C:\\triage を実行すると、winevt\\Logs\\ 配下のすべての .evtx を一度にチェーン・オブ・カストディのメタデータ付きで取得できます。WindowsEventLogs モジュールと組み合わせれば収集と同時にパースも可能です。"
    - name: "生の NTFS 読み取り"
      text: "改ざんが疑われる場合は、RawCopy または tsk_recover でファイルシステム層の下（\\\\.\\PhysicalDriveN または \\\\.\\C:）からボリュームを開き、MFT から各 .evtx をバイト単位で読み出します。EventLog サービスはこのパスをブロックできません。"
---

イベントログ調査で最初に立ちはだかるのはパースではなく、*ファイルを入手すること*です。稼働中の Windows ホストでは、EventLog サービスが `C:\Windows\System32\winevt\Logs\` 配下の active な [`.evtx` ファイル](/ja/blog/what-is-an-evtx-file) にハンドルを保持しているため、素朴な `copy` は失敗します。次の 4 つのアプローチでほぼ全ケースをカバーできます。

## ビルトイン：wevtutil / Get-WinEvent

もっとも簡単な方法は、ドキュメント化された API 経由で（ファイルではなく）レコードをエクスポートする方法です。

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

これによりログ内の全レコードを含む封印済みの `.evtx` が生成されます。手軽でサードパーティ ツール不要、管理者権限で実行できます。デメリットは、アーカイブ（ローテートされた）`.evtx` ファイルは取得できず、active なものしか扱えないことです。

PowerShell での等価操作。

```powershell
Get-WinEvent -LogName Security |
  Export-Csv triage.csv
```

`Get-WinEvent` はパース済みレコードを返し、ファイル自体は返しません。クイックなトリアージ CSV としては有用ですが、より深いフォレンジック — [チャンク レベルのリカバリ、dirty チャンクの検査、カービング](/ja/blog/evtx-file-format-chunks) — に必要なバイナリの忠実性は失われます。

## FTK Imager

完全なディスクまたはファイルシステム レベルの取得には FTK Imager が定番です。稼働中のドライブを Evidence（Physical Drive または Logical Drive）として追加し、`\Windows\System32\winevt\Logs\` まで移動して各チャネル ファイルを右クリックし、Export Files を選びます。FTK は基底の NTFS 構造を直接読み取るため、EventLog サービスが保持するファイルシステム ロックをバイパスできます。`wevtutil` が触れないアーカイブ済み `*.evtx` ファイル（名前にタイムスタンプが含まれるもの）もエクスポートできます。

トレードオフとして、FTK は書き込み途中のファイルを読み取る可能性があり、結果として末尾チャンクが dirty な `.evtx` になることがあります。ほとんどのパーサ（[本サイトのものも含む](/ja/blog/how-to-open-an-evtx-file)）はこれを問題なく扱えますが、検証する価値はあります。

## KAPE

スケールするインシデント対応には、Kroll Artifact Parser and Extractor（KAPE）が、フォレンジック上関連するファイルすべての収集をワンパスで自動化します。

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

`EventLogs` ターゲットは `winevt\Logs\` 配下のすべての `.evtx` と、関連するイベント トレース ファイルを取得します。`WindowsEventLogs` モジュールと組み合わせれば、即時パースを実行して生ファイルに加えて CSV を生成できます。複数ホストにまたがる IR エンゲージメントには必須です。

## 生の NTFS 読み取り

最大限の忠実性が必要な場合 — 稼働中のファイルシステム API が傍受されている疑いがある、あるいはビットレベル取得を行いたい場合 — ファイルシステム層の下からボリュームを読み取ります。[The Sleuth Kit](https://www.sleuthkit.org/)（`tsk_recover`、`icat`）や Eric Zimmerman の `RawCopy.exe` といったツールは、`\\.\PhysicalDriveN` または `\\.\C:` 経由でボリュームをオープンし、MFT をたどってファイル内容をバイト単位で取り出します。EventLog サービスはこの経路をブロックできません。読み取りがファイルシステム層を完全にバイパスするためです。

## どれを使うか

- **1 台のホストでクイック トリアージ、管理者権限あり**:`wevtutil`。
- **完全なフォレンジック取得、ディスク イメージが既にある**:イメージに対して FTK Imager または `tsk_recover`。
- **IR エンゲージメント、複数ホスト**:KAPE。
- **ルートキットや稼働中の改ざんの疑い**:稼働ボリュームに対して RawCopy または TSK での生の NTFS 読み取り、ホストはネットワークから隔離。

何を選ぶにせよ、必ず記録してください。インシデント報告書では証拠の出所連鎖が重要です — パース済み CSV だけでは、それが EventLog サービスが動いている稼働ホストから来たのか、封印済みイメージから来たのかは何も語りません。

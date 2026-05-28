---
title: "稼働中の Windows システムから .evtx ログを収集する方法 (4 種類)"
description: "ライブの Windows ホストから .evtx を取り出す 4 つの方法: wevtutil、FTK Imager、KAPE、生 NTFS。それぞれの証拠保全上のトレードオフと、実際に実行するコマンドを紹介します。"
date: "2026-05-17"
howto:
  name: "稼働中の Windows システムから .evtx ログを収集する方法"
  steps:
    - name: "wevtutil でエクスポート"
      text: "管理者として wevtutil epl Security C:\\triage\\Security.evtx を実行し、ライブ ファイルに触れずにアクティブな Security チャネルの可搬コピーを封緘します。"
    - name: "FTK Imager で取得"
      text: "FTK Imager を開き、Add Evidence Item で \\Windows\\System32\\winevt\\Logs\\ に移動し、チャネル ファイル (アーカイブされた *.evtx を含む) を選択して Export Files を実行します。FTK は NTFS を直接読み取るので、EventLog サービスのファイル ロックを回避できます。"
    - name: "KAPE でまとめて収集"
      text: "kape.exe --tsource C: --target EventLogs --tdest C:\\triage を実行し、winevt\\Logs\\ 配下のすべての .evtx を一括で取り出します。証拠連鎖メタデータも付きます。WindowsEventLogs モジュールと組み合わせれば、収集時にパースまで行います。"
    - name: "生 NTFS 読み取り"
      text: "改ざんが疑われる場合は、RawCopy または tsk_recover でファイルシステム層より下 (\\\\.\\PhysicalDriveN または \\\\.\\C:) からボリュームを開き、MFT から各 .evtx をバイト単位で読み取ります。EventLog サービスはこの経路をブロックできません。"
---

イベント ログ案件で最初の難所はパースではありません。EventLog サービスに手を払われずにファイルをホストから取り出すことです。動いている Windows では、サービスは `C:\Windows\System32\winevt\Logs\` のアクティブな [`.evtx` ファイル](/ja/blog/what-is-an-evtx-file) のハンドルを保持しています。したがって素朴な `copy` は共有違反エラーで返ります。私が遭遇したほぼすべてのケースは、次の 4 つの方法でカバーできます。

## wevtutil と Get-WinEvent: 組み込み、最速

最も安価な経路は Microsoft 公式 API を使います。

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

これでチャネル内の現行レコードすべてを含む封緘済み `.evtx` が作れます。サードパーティ ツール不要、管理者シェルが必要です。声に出して言うべき注意点: `epl` はアクティブ ログしかキャプチャしません。同じディレクトリの `Archive-Security-*.evtx` ファイルは取り残されます。直近でローテーションがあり、目的のレコードがアーカイブにある場合、この方法では取り逃します。

PowerShell は代わりにパース済みレコードを返します。

```powershell
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Security.evtx |
  Export-Csv triage.csv -NoTypeInformation
```

これは `.evtx` ではなく CSV を出します。ホスト上の即席トリアージには便利。しかし[チャンク レベルの復旧、ダーティ チャンクの検査、未割り当て領域からのカービング](/ja/blog/evtx-file-format-chunks) には役に立ちません。バイナリの忠実性を捨ててしまっているからです。

## FTK Imager: NTFS レベル取得

レコードではなくファイルが欲しいときは、FTK Imager が常用ツールです。ライブ ドライブを Evidence として追加 (Physical Drive または Logical Drive)、`\Windows\System32\winevt\Logs\` に移動、チャネル ファイルを右クリックして Export Files。FTK は基底の NTFS 構造を直接読み取るので、EventLog サービスが保持しているファイルシステム ロックを迂回します。`wevtutil epl` がスキップするアーカイブ `Archive-*.evtx` ファイルもキャプチャします。

トレードオフ: FTK は書き込み途中のファイルを読むことがあります。アクティブ チャネルの末尾チャンクがダーティになることもあります。多くのパーサーはこれを正常に処理します ([本サイトのブラウザ パーサー](/ja/blog/how-to-open-an-evtx-file) を含む) が、報告書に書く前に検証台で確かめてください。取得中に EventLog サービスが非標準的な動作をしたと疑われる場合、対応する [USN journal](https://www.usnparser.com) エントリは有用な裏付けになります。

## KAPE: IR 速度の一括収集

エンゲージメントに複数のホストが含まれる場合、Kroll Artifact Parser and Extractor は 1 時間以内に元が取れます。

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

`EventLogs` ターゲットは `winevt\Logs\` 配下のすべての `.evtx` と関連 ETW ファイルを一掃します。`!EZParser` または `WindowsEventLogs` モジュールと組み合わせると、KAPE は終了時にコレクションに対して EvtxECmd も実行し、生の証拠と並べてパース済み CSV も生成します。ついでに `RegistryHives` と `FileSystem` ターゲットで、どのみち欲しい [registry](https://www.registryparser.com)、[MFT](https://www.mftparser.com)、[USN journal](https://www.usnparser.com)、[prefetch](https://www.prefetchparser.com) データも取得します。

KAPE の出力にはコピー ログ メタデータが付属します。これは、人々が評価する以上に証拠連鎖にとって重要です。

## 生 NTFS 読み取り: 改ざんが疑われるとき

最大の忠実性が必要なら、ファイルシステム層より下に降ります。Sleuth Kit の `tsk_recover` と `icat`、または Eric Zimmerman の `RawCopy.exe` は、`\\.\PhysicalDriveN` または `\\.\C:` 経由でボリュームを開き、MFT を歩いて、ファイル内容をバイト単位で出力します。Win32 ファイル API を経由しないので、EventLog サービスはこれをブロックできません。

ルートキットがスコープに含まれるとき、カーネル フィルタ ドライバが `\winevt\Logs\` の読み取りを傍受していると疑う理由があるとき、または単に動いている OS を信頼しないときに、これを使います。同時刻に取った [RAM dump](https://www.ramparser.com) と組み合わせてください。イベント ログ サービスは最近のレコードをメモリにキャッシュしており、改ざんの数分前のスナップショットには、ディスクに到達しなかったレコードが含まれていることがあります。

## どれをいつ使うか

- 1 ホスト、管理者権限あり、1 時間あり: 重要な各チャネルに対して `wevtutil epl`、ディレクトリを zip、完了。
- すでにディスク イメージが手元にある: イメージに対して FTK Imager または `tsk_recover`。ライブ ホストより速く、SOC と調整する必要もありません。
- 複数ホスト、本格的な IR エンゲージメント: KAPE。スループットでこれに迫るものはありません。
- ライブ改ざんやルートキットが疑われる: ホストのネットワークを隔離した上で、ボリュームに対して RawCopy または TSK。

どれを選ぶにせよ、文書化してください。パース済み CSV は出所について何も語りません。ケース ノートに `KAPE 1.3.0.2 EventLogs target, hash file attached` と書く一行が、証拠物と意見との違いを生みます。

## 参考資料

- [KAPE ドキュメント](https://ericzimmerman.github.io/KapeDocs/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager)

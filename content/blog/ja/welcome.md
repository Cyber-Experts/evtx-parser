---
title: "ここから始める: DFIR アナリストのための .evtx ガイド"
description: ".evtx とは何か、重要なチャネル、押さえておくべき Event ID、それぞれがディスク上のどこにあるか。このブログのその他すべてのコンテンツへの出発点となるナビゲーションです。"
date: "2026-05-16"
updated: "2026-05-24"
---

`.evtx` は、Microsoft が Vista から導入したバイナリの Windows イベントログ形式で、旧来の `.evt` を置き換えました。Windows のインシデント対応の背骨です。ログオン、サービス インストール、スケジュールド タスク、PowerShell コマンドライン、Sysmon のプロセス ツリー。すべてこの形式にシリアライズされます。本記事は索引です。1 画面で全体像を示してから、実際の事案で意味のあるチャネルと Event ID を扱う各記事へのリンクをまとめます。

`.evtx` に初めて触れる方は、まず [.evtx ファイルとは何か](/ja/blog/what-is-an-evtx-file) と [.evtx ファイルの開き方](/ja/blog/how-to-open-an-evtx-file) からどうぞ。本記事の残りは、形式に慣れていて、ホストが炎上したときにまず何を読むべきかを知りたい方を想定しています。

## ファイルの場所

ライブのログは `C:\Windows\System32\winevt\Logs\` の下にあります。1 チャネルにつき 1 つの `.evtx` ファイルです。常に存在するデフォルト:

- `Security.evtx`。ログオン、特権利用、監査ポリシー変更。ほとんどの事案で最もフォレンジック価値が高い。
- `System.evtx`。ドライバー、サービス、OS レベルのエラー。
- `Application.evtx`。アプリケーション レベルのエラー。
- `Setup.evtx` と `ForwardedEvents.evtx`。インストール記録と転送された WEF トラフィック。

加えて `Microsoft-Windows-*` 配下のアプリケーション別チャネル。事案で本領を発揮するもの:

- `Microsoft-Windows-Sysmon%4Operational.evtx`。Sysmon が入っているときだけ存在します。入っていれば金脈です。
- `Microsoft-Windows-PowerShell%4Operational.evtx`。Scriptblock とモジュール ロギング。
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`。スケジュールド タスクの作成と実行。
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`。RDP セッションのライフサイクル。

ファイルがどのようにレイアウトされているか(64 KB チャンク、XML テンプレート テーブル、BinXML)の深掘りは、[チャンク レベルの詳細](/ja/blog/evtx-file-format-chunks) を参照してください。

## 押さえておくべき Event ID

アナリストが軸にする項目の大半をカバーする要点リスト:

- [**4624** ログオン成功](/ja/blog/understanding-event-id-4624)。`LogonType` で読み解きます。このフィールドが、コンソール (2)、ネットワーク (3)、RDP (10)、`runas /netonly` (9) のどれを見ているかを決めます。
- [**4625** ログオン失敗](/ja/blog/detecting-4625-brute-force)。バースト パターンは、どのフィールドが集まっているかによって、偵察、ブルートフォース、パスワード スプレーのいずれかになります。
- [**1102** Security ログがクリアされた](/ja/blog/event-id-1102-cleared-log)。これを見たら、手元のログには既知の欠落があります。報告書に大きく明記してください。
- [**4104** PowerShell scriptblock](/ja/blog/powershell-4104-scriptblock)。デコードとリフレクションの*後*のスクリプト本体。プラットフォーム上で最も有用な無料の防御制御です。
- [**7045** サービス インストール](/ja/blog/service-creation-event-id-7045)。MITRE ATT&CK で最も引用される永続化テクニックの 1 つ (T1543.003)。PsExec のシグネチャでもあります。
- [**Sysmon 1** プロセス作成](/ja/blog/sysmon-event-id-1-process-create)。Sysmon が存在する場合、Windows が生成できる最も豊富なプロセス作成記録です。

それらをつなぎ合わせるワークフローについては、[1 時間と 1 台のホストがあるときの EVTX トリアージ](/ja/blog/evtx-triage-incident-response) を読んでください。

## このサイトの位置づけ

トップ ページのパーサーは Rust クレート [omerbenamram/evtx](https://github.com/omerbenamram/evtx) を WebAssembly にコンパイルし、Web Worker 上で動かしています。`.evtx` をドロップすると、ワーカーがチャンクを走査し、フィルタ可能なイベント タイムラインとレコードごとの XML を返します。すべてブラウザ内で完結し、アップロードはありません。EDR を立ち上げたくないとき、自分のものではないシステムからファイルを移動させたくないときの、即席トリアージに使ってください。

[ライブ ホストから `.evtx` を収集する](/ja/blog/collecting-evtx-from-live-system)(KAPE、FTK Imager、`wevtutil`)場合は、その記事で 4 つの標準的な手法と、それぞれの証拠保全上のトレードオフを扱っています。

EVTX が必要な唯一のアーティファクトであることは稀です。[registry](https://www.registryparser.com)、[MFT](https://www.mftparser.com)、[USN journal](https://www.usnparser.com)、[AmCache](https://www.amcacheparser.com)、[Shimcache](https://www.shimcacheparser.com)、[prefetch](https://www.prefetchparser.com)、[LNK](https://www.lnkparser.com) のパーサーと組み合わせてください。さらに深く掘る必要があるときは、[pagefile](https://www.pagefilesysparser.com) と [RAM dump](https://www.ramparser.com) の解析が、ディスク常駐ログでは失われたものを復元します。ユーザー活動のタイムラインには、[SRUM](https://www.srumparser.com)、[jump lists](https://www.jumplistparser.com)、[recycle bin](https://www.recyclebinparser.com)、[recent file cache](https://www.recentfilecacheparser.com)、[browser history](https://www.browserforensics.app) が、EVTX では埋められない空白を埋めます。

---
title: "PowerShellロギング: モジュールロギングとスクリプトブロックロギングを有効にすると何が得られるか"
description: "PowerShellのモジュールロギング、スクリプトブロックロギング、トランスクリプト、AMSIバッファの実用的な違いと、本当に役立つものを有効にするGPO設定について。"
date: "2026-05-27"
tags:
  - evtx
  - powershell
  - dfir
  - logging
  - threat-hunting
author: "Florian Amette"
---

注目すべきあらゆる攻撃者ツールキットは、どこかでPowerShellを実行します。Cobalt Strikeビーコンはそれを起動します。EmpireとCovenantはそれを基盤としています。living-off-the-landガイドはそれから始まります。良いニュースは、PowerShell 5.0以降、Microsoftは正しく設定されれば、難読化されたペイロードを難読化解除後を含めて、PowerShellが実行するすべてのものの文字通りのテキストをキャプチャするロギングを提供していることです。悪いニュースは、「正しく設定されれば」という部分が大きな意味を持っていることです。私が訪れるほとんどの環境では、4つの関連ログのうち1つだけが有効で、4つすべてではなく、最も有用なものでもありません。

この投稿では、実際に何が得られるか、何を有効にする価値があるか、そしてどこにギャップがあるかを説明します。

## 4つのログ、有用性の順

PowerShellは `Microsoft-Windows-PowerShell%4Operational.evtx` に書き込みます。重要なイベントIDは:

- `4104` script block logging。PowerShellがコンパイルして実行するすべてのスクリプトブロックの文字通りのテキスト。ブロックが組み込みのヒューリスティクスによって疑わしいとフラグ付けされた場合、Warning重大度でログに記録されます。それ以外の場合はVerboseで、これはデフォルトでオフです。これが望むイベントです。
- `4103` module logging。モジュールごとのパイプライン実行を、パラメーターバインディングと共に記録します。`4104` ほどの散文性はなく、より構造化されています。スクリプト本体なしで「どのcmdletが実行されたか」に有用です。
- `4105` と `4106` pipeline startedとpipeline stopped。括弧付けに有用で、内容には不向きです。
- `400` / `403` (レガシー、PowerShell 2.0時代) engine state changes。フォレンジック歴史的なイベント。誰かがPS 2.0ダウングレード攻撃を強制したホストでまだこれらを見ます。

正確に1つだけオンにできるなら、`4104` をVerboseでオンにしてください。それ以外はすべて補助的です。

## `4104` が実際にキャプチャするもの

`4104` イベントには、PowerShellがコンパイルしたとおりのスクリプトブロックの完全なテキストが含まれます。「PowerShellがコンパイルしたとおり」から2つのことが続きます:

- イベント内のテキストは、ほとんどの場合 *難読化解除後* の表現です。オペレーターが `iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...')))` を実行すると、外側の `iex` 呼び出し (これ自体が `4104`) と、PowerShellがそのブロックを実行するためにコンパイルしなければならなかったため、内側のデコードされたスクリプトブロックのための *2番目の* `4104` の両方を取得します。これは `4104` ロギングの唯一最も価値のあるプロパティです。
- 大きなスクリプトは、イベントデータの `MessageNumber` と `MessageTotal` を使用して複数のイベントに分割されます。50 KBのスクリプトは、分析前に再構築しなければならない一連のイベントになります。ほとんどのツールはこれを行いますが、一部は行いません。パーサーがフラグメントを表示している場合、チェーンを処理するかどうかを確認してください。

`Path` フィールドは、ソースファイルがあった場合はそれを示します。空の `Path` と完全にインラインされたスクリプト本体は「これはネットワーク経由またはメモリ外から来た」を意味し、スケジュールされたスクリプトと対話的なオペレーターアクティビティを見つけるための単一の最良のヒューリスティクスです。

`ScriptBlockId` はGUIDです。同じホストでの同じブロックの再実行は通常、(キャッシュのため) GUIDを再利用します。これは、クロスホスト検索ができるSIEMがある場合、「このコードが実行されたすべてのホスト」を見つけるのに便利です。

## モジュールロギング: `4103` が追加するもの

モジュールロギングはスクリプトブロックロギングより古く、よりノイジーです。パイプライン実行レイヤーにフックするので、ログに記録されたモジュール内のすべてのcmdlet呼び出しに対して、cmdlet名、バインドされたパラメーター、ペイロード文字列を持つ `4103` を取得します。

現代のIRでは、`4103` は3つのケースで最も有用です:

- 攻撃者が興味深いパラメーターをバインドするcmdletを使用した場合 (`Invoke-WebRequest -Uri ...`、`New-Object Net.Sockets.TcpClient ...`、`Get-WmiObject -Class Win32_ShadowCopy`)。`4104` はソースを示します。`4103` は変数展開後の解決済みパラメーター値を示します。
- 攻撃者がエンコードされたコマンドを使用した場合。`powershell -enc <base64>` は、対応する `4104` が発行される前に、デコードされたテキストがペイロードに含まれる `4103` を生成します。
- 攻撃者が `4104` を無効にした場合 (ローカル管理者権限があればレジストリ編集で達成可能)。`4103` は別のロギングパスの下に存在し、`4104` が無効にされても残ることがあります。

注意点: モジュールロギングは明示的に有効にされたモジュールのみをログに記録します。GPO設定では `*` (すべてをログに記録) またはモジュール名のリストが必要です。ロギングを真剣に受け止めるあらゆる環境では `*` が答えです。聞こえる「パフォーマンスへの影響」の反対意見は、非常に重いPowerShellワークロードでは現実的であり、通常のフリートデスクトップでは間違っています。

## トランスクリプトはスクリプトブロックログではない

「Turn on PowerShell Transcription」という別の設定があり、すべてのセッションの入力と出力を設定されたディレクトリの下のテキストファイルに書き込みます。これは `4104` と同じものではなく、人々は常にこれらを混同しています。

重要な違い:

- トランスクリプトにはcmdletの *出力* が含まれます。`4104` には含まれません。`Get-ADUser` が実際に何を返したかを知りたい場合は、トランスクリプトがそれです。
- トランスクリプトはテキストファイルです。侵害されたホストでは簡単に削除可能で簡単に変更可能です。`4104` イベントは、ログクリアまたはそれ以上でなければ妨害できないEVTXチャネルに送られます。
- `OutputDirectory` が設定されていない限り、トランスクリプトはデフォルトでユーザーのドキュメントフォルダになります。`OutputDirectory` を書き込み専用ネットワーク共有に設定しない場合、トランスクリプトは証拠ではありません。礼儀です。

`OutputDirectory` を、書き込みユーザーが書き込み専用NTFS権限 (読み取りなし、削除なし) を持つUNCパスに向けてトランスクリプトをオンにしてください。これは、攻撃者に自分の履歴を変更または削除するオプションを与えることなく、`4104` が提供しないcmdlet出力の足跡を提供します。

## AMSIとバッファの観点

AMSI (Antimalware Scan Interface) は、Defenderや他のAV製品が実行前にPowerShellスクリプトのコンテンツを検査できるようにするランタイムフックです。フォレンジックへの2つの結果:

- 攻撃者がPowerShellロギングを無効にした場合でも、AMSIは実行直前にスクリプトのコンテンツを見ます。そしてコンテンツがシグネチャに一致する場合、Defenderは `Microsoft-Windows-Windows Defender%4Operational.evtx` に `1116` または `1117` をログに記録します。Defenderイベントには、脅威検出レコードにスクリプトテキストが部分的に含まれます。スクリプトブロックロギングがオフだったホストでは、これが悪意のあるコードが存在する唯一の場所であることがあります。
- 攻撃者が使用する「AMSIバイパス」テクニック (`amsi.dll!AmsiScanBuffer` のメモリ内パッチ、偽造された `AmsiContext` の提供、AMSIプロバイダーのCOMハイジャック) 自体は、バイパスが効果を発揮する *前に* 、通常バイパスコードの `4104` イベントを生成します。バイパスはロギングを遡及的にオフにすることはできません。したがって、オペレーターがAMSIを正常に無効化したホストでも、彼らがそれをした瞬間は記録されています。

`4104` で探すべきパターン: `amsiInitFailed`、`AmsiScanBuffer`、`VirtualProtect`、または `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` を含む小さなスクリプトブロック。これらはあらゆる一般的なバイパスのシグネチャです。

## ロギングをオンにする

GPO設定は `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell` の下にあります。有効にしたい3つ:

- "Turn on PowerShell Script Block Logging" enabled。括弧付けの `4105`/`4106` イベントが欲しい場合は "Log script block invocation start / stop events" にチェックを入れます。デフォルトではオフで、通常はボリュームに見合いません。
- "Turn on Module Logging" enabled。モジュール名: `*`。
- "Turn on PowerShell Transcription" enabled。`OutputDirectory`: UNCパス。`Include invocation headers`: チェック。

GPOの外で設定する場合の対応するレジストリパス:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    EnableModuleLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames
    * = *
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    EnableTranscripting = 1
    OutputDirectory = \\logserver\transcripts$
```

調査が必要になるマシンを含むOUに適用します。それは、真剣な組織では「それらすべて」です。

## 調査中にこれがどのように見えるか

スクリプトブロックロギングがオンだった侵害は、順番に次のことを教えてくれます:

1. 非標準の親からの自明でないスクリプトブロックを持つ最初の `4104`。最初の実行時刻。
2. ローダーが自己解凍するときの `4104` のチェーン。難読化の各層が剥がされ、ログに記録されます。
3. C2フレームワークのランタイムcmdlet (Invoke-Beacon、Invoke-Mimi、`Invoke-Kerberoast`、すべての一般的な攻撃用cmdlet名とその改名バリアント)。
4. 対話的オペレーターのキーボード操作コマンド。これらは記録されたシェルセッションのように読めます。それがまさに彼らです。

[Prefetch](https://www.prefetchparser.com) と相互参照して `powershell.exe` がいつ実行されたかを見つけ、オペレーターが開いたファイルの[LNKファイル](https://www.lnkparser.com)、PowerShellバイナリ自体のハッシュ ([AmCache](https://www.amcacheparser.com) を見る、時々名前が変更されます)、そして読んでいるイベントの時刻にロギングが本当にオンだったことを確認するためのGPO状態の[レジストリ](https://www.registryparser.com)を確認します。

スクリプトブロックロギングがオフだった侵害は、PowerShellについてはほとんど何も教えてくれず、検出体制について多くのことを教えてくれます。まずそれを修正してください。

## さらなる読み物

- Microsoftの[PowerShellロギングドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)。公式リファレンス。
- FireEye / Mandiantの[Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility)投稿。古いですが、依然として最もクリーンな現場視点の記事です。
- Daniel Bohannonの[Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation)プロジェクト。`4104` 分析を補完する難読化解除ツールキット。

---
title: "Event ID 4769 を解読する:Kerberos サービス チケットとケルベロースト"
description: "4769 は DC が発行する各サービス チケット要求のレコード。暗号化タイプで読めばケルベローストが、4768 と読めば pass-the-ticket が見える。"
date: "2026-05-24"
---

Event ID **4769** — 「Kerberos サービス チケットが要求されました」 — は、任意のアカウントがサービス用 TGS（Ticket Granting Service）チケットを要求するたびに、すべてのドメイン コントローラで発火します。すべての SMB 接続、すべての SQL ログイン、すべての Web SSO ヒットは、要求を処理した DC のいずれかでこのレコードを生成します。忙しい DC では最高ボリュームの [Security チャネル](/ja/blog/what-is-an-evtx-file) レコードであり — クラックされる前にケルベロースト が確実に現れる唯一の場所です。

ドメイン コントローラから 3 つの Security レコードを計測できるなら、その 1 つはこれです。

## どこに記録されるか

`4769` は**発行ドメイン コントローラ**の `Security` チャネルに書かれます — クライアントでもターゲット サービスでもありません。ドメインのすべての 4769 レコードを見るには、すべての DC から収集する必要があります。DC 上の KAPE の `EventLogs` ターゲット、または WEF でコレクタへ `Security` 転送のどちらでも機能します。WEF ルートが多くの成熟した現場で使われます。

## レコードの中身

```xml
<Data Name="TargetUserName">alice@CORP.LOCAL</Data>
<Data Name="TargetDomainName">CORP.LOCAL</Data>
<Data Name="ServiceName">MSSQLSvc/db01.corp.local:1433</Data>
<Data Name="ServiceSid">S-1-5-21-...-1234</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">50213</Data>
<Data Name="Status">0x0</Data>
<Data Name="LogonGuid">{...}</Data>
<Data Name="TransmittedServices">-</Data>
```

トリアージを駆動するフィールド。

- **`TargetUserName`** — *要求者*（ユーザー アカウント、`user@DOMAIN` 形式）。
- **`ServiceName`** — 要求された SPN。ここに（`host/...` やサービス クラスではなく）ユーザー アカウントがあるのは不審。
- **`TicketEncryptionType`** — このレコードが重要かを決める値。モダンなドメインは `0x12`（AES-256-CTS-HMAC-SHA1-96）か `0x11`（AES-128）で動きます。**`0x17` は RC4-HMAC** — レガシー、脆弱、Mimikatz/Rubeus の `kerberoast` モードが要求する*唯一の*暗号化タイプです。ユーザー アカウントのサービス チケットに対する `0x17` の 4769 は教科書的なケルベロースト指紋。
- **`Status`** — `0x0` は成功。それ以外は拒否（ステータス コードは `[MS-KILE]` にドキュメント化）。
- **`IpAddress`** — 要求ホスト。セッションを生んだログオンを見るため、そのホストの [4624](/ja/blog/understanding-event-id-4624) と組み合わせ。

## TicketEncryptionType — 重要なフィールド

完全な表（要約）。

| 値 | アルゴリズム | ステータス |
|---|---|---|
| 0x01 | DES-CBC-CRC | Win7 以降デフォルト無効 |
| 0x03 | DES-CBC-MD5 | Win7 以降デフォルト無効 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | モダン |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | モダン（ほとんどのアカウントのデフォルト） |
| **0x17** | **RC4-HMAC-MD5** | **レガシー。ケルベローストに必須。** |
| 0x18 | RC4-HMAC-EXP | 輸出グレード RC4、極稀 |

ドメインがベースライン化されサービス アカウントの `msDS-SupportedEncryptionTypes` が AES のみに設定されていれば、それらのアカウントに対して `0x17` は一切現れないはずです。攻撃者は明示的に `0x17` を要求します。RC4 暗号化されたサービス チケットのクラックは計算的に安価で、AES はそうではないからです。クラッキング ツールは RC4 ハッシュが必要なので、要求は 0x17 で*なければなりません*。

これがレコード上で最高シグナルの単一フィールドです。

## ケルベローストのパターン

ケルベロースト（MITRE T1558.003）はこう動作します。

1. 攻撃者は任意のドメイン ユーザー アカウントで認証（管理者権限不要）。
2. 攻撃者はユーザー アカウントに登録された SPN を列挙（コンピュータ アカウントではなく）。通常 LDAP の `(servicePrincipalName=*)` をユーザー オブジェクトに絞ったフィルタ。
3. 攻撃者は標準 Kerberos プロトコル経由で各 SPN の TGS を `etype=23`（RC4）で要求。**これが探している 4769。**
4. DC は喜んでチケットを発行、*サービス アカウントの* NTLM ハッシュで暗号化。
5. 攻撃者は暗号化ブロブをメモリ（または通信線）から引き出し、Hashcat（`-m 13100`）でオフライン クラック。

4769 の指紋。

- `ServiceName` が `MSSQLSvc/...`、`HTTP/...`、`LDAP/...`、または*ユーザー*アカウントを指す任意の SPN（`host/...` や `cifs/...` のようなコンピュータ アカウントではない）。
- `TicketEncryptionType` が `0x17`。
- 同じ送信元から多数の SPN に対するこれらの要求が短時間にバーストするのが決定的サイン。

2 つ目の関連パターン — **AS-REP roasting**（T1558.004）— は [4768](/ja/blog/event-id-4768-kerberos-tgt) を使い（TGT 要求）、`DONT_REQUIRE_PREAUTH` 設定アカウントを標的にします。レコードは違うが攻撃ファミリは同じです。

## Pass-the-ticket / golden / silver チケット

4769 はチケット偽造も明かしますが、シグナルはより微妙です。

- 妥当なウィンドウ内に同じホストの同じ `LogonGuid` で先行する 4768（TGT 要求）が*ない* 4769 — **ゴールデン チケット**疑惑。攻撃者は偽造 TGT を提示し、本物の TGT を要求せずに直接 TGS 要求に進みました。
- 4769 とその結果のターゲット上のサービス認証があるが、どの DC にも 4769 が*見えない* — **シルバー チケット**疑惑。攻撃者は TGS 自体を偽造し、DC は要求されなかった。
- ターゲット サービス上の 4624 とチケットを発行したとされる 4769 の `LogonGuid` 不一致 — 偽造チケット。

これらは不在による検知パターンなので、すべての DC とターゲット サービスにわたる完全なログ カバレッジが必要です。WEF カバレッジのギャップは同じに見える誤検知を生むので、アラート前に収集を特性化してください。

## トリアージ ワークフロー

1. DC コーパスのすべての 4769 を `TicketEncryptionType == 0x17` でフィルタ。
2. 30 分ウィンドウで `IpAddress` と `TargetUserName` でグルーピング。送信元あたりの distinct な `ServiceName` をカウント。
3. 30 分で 1 つの送信元から 0x17 として要求された distinct SPN が 3 を超えるなら、ほぼどこでもケルベロースト。
4. 送信元 IP を元ホストの [4624](/ja/blog/understanding-event-id-4624) にピボット — 攻撃を起動した資格情報を見つける。
5. 要求された SPN を所有するサービス アカウントにピボット。それらのパスワードをローテーション。クラック済みハッシュは日単位ではなく時間単位でリセット。

## サンプル Sigma ルール

```yaml
title: Kerberoasting via RC4 Service Ticket Request
id: 9bb37f72-3a4f-4a3a-9d8e-3a91c4f74a0f
status: stable
description: Service ticket requests using RC4 encryption type for SPNs registered to user accounts.
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|startswith:
      - 'MSSQLSvc/'
      - 'HTTP/'
      - 'TERMSRV/'
      - 'LDAP/'
  filter_machine:
    ServiceName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Legacy applications that only support RC4
  - Pre-AES domains still in transition
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

`filter_machine` 句はコンピュータ アカウント SPN（常に `$` で終わる）を除外します。ケルベローストはユーザー アカウント SPN のみを標的とします。

## サンプル KQL / Splunk

KQL（Defender XDR / Sentinel、`SecurityEvent` 経由）:

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize SPNs=dcount(ServiceName), Services=make_set(ServiceName, 10)
    by IpAddress, TargetUserName, bin(TimeGenerated, 30m)
| where SPNs >= 3
| order by TimeGenerated desc
```

Splunk:

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## ATT&CK マッピング

4769 コーパスのカバー範囲。

- **T1558.003 — Kerberoasting**:目玉のユース ケース。
- **T1558.001 — Golden Ticket**:同じ `LogonGuid` からの 4768 がない 4769。
- **T1558.002 — Silver Ticket**:ターゲットで観測されたサービス認証に対する 4769 がない。
- **T1078 — Valid Accounts**:既知サービス アカウントに対する想定外 IP からの 4769。
- **T1550.003 — Pass the Ticket**:4769 の後に `LogonProcessName: Kerberos` の [4624](/ja/blog/understanding-event-id-4624) LogonType 3。

## 見える誤検知

- **レガシー アプリケーション**（一部の古い SQL Server コネクタ、一部の Java/JBoss アプリ）は明示的に RC4 を要求します。安定したホストの小さなセットからの定常的な日中 0x17 トラフィックとして現れます。ベースライン化して除外。
- **AES 移行前のドメイン**は、Kerberos ハードニング移行中、すべてのアカウントに `msDS-SupportedEncryptionTypes` が設定されるまで 0x17 を広範に出します。煩わしいが悪意はない。
- **脆弱性スキャナ**（Tenable、Qualys、BloodHound 列挙スクリプト）はケルベロースト トラフィックを複製。スキャナ ホストにタグ。
- **アカウント移行ツール**はクロスフォレスト移動中に異常なチケット組み合わせを要求し得る。

シグナルは*バースト*パターンで、個別レコードではありません。1 つのホストからの定常的な 0x17 は設定。1 つのホストから数分以内に多数の SPN へのバースト的 0x17 が攻撃です。

## 4769 では分からないこと

レコードには暗号化されたチケット自体は含まれません — クラッキングは攻撃者がエクスフィルしたものに対して行われ、DC からの通信線上ではありません。4769 単体では、「チケットが発行されたが使用されなかった」と「チケットがクラックされ資格情報が再利用された」を区別できません。連鎖の後半には、ターゲット サービス上の結果としての [4624](/ja/blog/understanding-event-id-4624)（LogonType 3、AuthenticationPackage Kerberos）、可能なら資格情報再利用後に何が動いたかを示す [4688](/ja/blog/event-id-4688-process-creation) または [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) が必要です。4769 はカナリアであってアラームではないと扱ってください。

## タイムラインにおける 4769 の位置

古典的な侵害後ケルベロースト連鎖。

1. ワークステーション上の [**4624**](/ja/blog/understanding-event-id-4624) — フィッシングされたユーザー資格情報による初期アクセス。
2. そのワークステーション IP から 1 つの DC への **4769** ×N、すべて `etype=0x17`、すべて 5 分以内のユーザー SPN サービス アカウント標的 — ケルベロースト。
3. *(オフライン、不可視)* — 攻撃者は最も弱いサービス アカウントのハッシュを Hashcat でクラック。
4. **4768** — 侵害サービス アカウントとしての TGT 要求、別のホストから。
5. **4624** 高価値サーバ上の LogonType 3、AuthenticationPackage Kerberos、サービス アカウント使用。
6. [**7045**](/ja/blog/service-creation-event-id-7045) — 侵害アカウント下で永続化のためにサービス インストール。

ステップ 2 の 4769 バーストが最も早く、最も安価な検知点 — 攻撃者がサービス アカウントとして戻ってくる数時間または数日前です。

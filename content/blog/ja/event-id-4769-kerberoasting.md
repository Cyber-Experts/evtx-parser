---
title: "Event ID 4769 を解説: Kerberos サービス チケットと kerberoasting"
description: "4769 は DC が発行したすべてのサービス チケット リクエストの記録です。暗号化タイプで読めば kerberoasting を、4768 と一緒に読めば pass-the-ticket を見つけられます。"
date: "2026-05-24"
---

Event ID **4769**「Kerberos サービス チケットが要求されました」は、任意のアカウントがサービスの TGS (Ticket Granting Service) チケットを要求するたびに、すべてのドメイン コントローラー上で発火します。すべての SMB 接続、すべての SQL ログイン、すべての Web SSO ヒットは、リクエストを処理した DC 上で 1 つ生成します。忙しい DC では [Security チャネル](/ja/blog/what-is-an-evtx-file) で最も大量のレコードであり、credential がオフラインで解読される前に kerberoasting が確実に現れる唯一の場所です。

DC から計装する Security レコードが 3 つだけなら、これがその 1 つです。

## どこに住むか

`4769` は発行**ドメイン コントローラー**の Security チャネルにのみ書かれます。クライアントには出ません。対象サービスにも出ません。ドメインのすべての 4769 レコードを見るには、すべての DC から収集する必要があります。DC 上の KAPE の `EventLogs` ターゲット、または WEF 経由のコレクターへの Security 転送、どちらも機能します。WEF は成熟したショップが使うものです。

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

トリアージを駆動するフィールド:

- `TargetUserName`。要求者 (ユーザー アカウント、`user@DOMAIN` 形式)。
- `ServiceName`。要求された SPN。ここがユーザー アカウント (`host/...` やサービス クラスではない) なのは怪しい。
- `TicketEncryptionType`。このレコードが重要かを決定するフィールド。現代のドメインは `0x12` (AES-256-CTS-HMAC-SHA1-96) または `0x11` (AES-128) で動作します。**`0x17` は RC4-HMAC**: レガシー、脆弱、Mimikatz と Rubeus の `kerberoast` モードが要求する*唯一*の暗号化タイプです。サービス アカウント チケットに対する `0x17` の 4769 は、教科書的な kerberoasting フィンガープリントです。
- `Status`。`0x0` は成功。それ以外は拒否 (コードは `[MS-KILE]` に文書化)。
- `IpAddress`。要求元ホスト。セッションを生成したログオンを見るため、そのホスト上の [4624](/ja/blog/understanding-event-id-4624) と組み合わせ。

## TicketEncryptionType: 決定するフィールド

| 値 | アルゴリズム | ステータス |
|---|---|---|
| 0x01 | DES-CBC-CRC | Win7 以降デフォルト無効 |
| 0x03 | DES-CBC-MD5 | Win7 以降デフォルト無効 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | 現代 |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | 現代 (多くのアカウントのデフォルト) |
| **0x17** | **RC4-HMAC-MD5** | **レガシー。kerberoasting に必要。** |
| 0x18 | RC4-HMAC-EXP | エクスポート グレード RC4、極稀 |

ドメインがベースライン化されていてサービス アカウントの `msDS-SupportedEncryptionTypes` が AES のみに設定されていれば、それらのアカウントに対して `0x17` は一切現れないはずです。攻撃者は明示的に `0x17` を要求します。RC4 で暗号化されたサービス チケットの解読は計算上安いからです。AES はそうではありません。クラッキング ツールは `0x17` を要求*しなければなりません*。

これはレコード上で最もシグナルの高いフィールドです。

## kerberoasting のパターン

Kerberoasting (T1558.003) はこう機能します:

1. 攻撃者は任意のドメイン ユーザーで認証 (管理者権限不要)。
2. 攻撃者はユーザー アカウント (コンピューター アカウントではない) に登録された SPN を列挙、通常 LDAP の `(servicePrincipalName=*)` をユーザー オブジェクトにフィルタ。
3. 攻撃者は標準 Kerberos プロトコル経由で、各 SPN に対して `etype=23` (RC4) で TGS を要求。あなたが探している 4769 です。
4. DC は喜んでチケットを発行し、サービス アカウントの NTLM ハッシュで暗号化します。
5. 攻撃者は暗号化された blob を取り出し、オフラインで Hashcat (`-m 13100`) で解読します。

4769 のフィンガープリント:

- `ServiceName` が `MSSQLSvc/...`、`HTTP/...`、`LDAP/...`、またはユーザー アカウントを指す SPN (`host/...` や `cifs/...` のようなコンピューター アカウントではない)。
- `TicketEncryptionType` が `0x17`。
- 短い時間枠内、同じ送信元から、多数の SPN に対するバースト。

関連パターン**AS-REP roasting** (T1558.004) は代わりに [4768](/ja/blog/event-id-4768-kerberos-tgt) を使い、`DONT_REQUIRE_PREAUTH` を持つアカウントを標的にします。別レコード、同じファミリ。

## Pass-the-ticket、golden、silver

4769 はチケット偽造も明かしますが、シグナルはより微妙です。

- 同じ `LogonGuid` の同じホストからの先行 4768 が*ない*妥当な期間内の 4769: golden ticket の疑い。攻撃者が偽造 TGT を提示し、まっすぐ TGS リクエストに進んだ。
- 4769 *と*ターゲット上の結果のサービス認証があり、どの DC 上にも 4769 が見えない: silver ticket の疑い。攻撃者は TGS 自体を偽造しました。DC は問われませんでした。
- ターゲット上の 4624 と、チケットを発行したとされる 4769 の間の `LogonGuid` 不一致: 偽造チケット。

これらは不在による検知パターンです。すべての DC とターゲット サービスにわたる完全なログ カバレッジが必要です。WEF カバレッジのギャップは同じように見える誤検知を生みます。アラート前にコレクションを特徴づけてください。

## トリアージ ワークフロー

1. すべての DC コーパスで `TicketEncryptionType == 0x17` の 4769 をフィルタ。
2. 30 分ウィンドウで `IpAddress` と `TargetUserName` でグループ化。ソースあたりの distinct `ServiceName` をカウント。
3. 30 分以内に 1 つの送信元から 3 つ超の異なる SPN が 0x17 として要求されたら、ほぼどこでも kerberoasting。
4. 攻撃を開始した資格情報を見つけるため、送信元 IP をその [4624](/ja/blog/understanding-event-id-4624) に軸を変える。
5. 要求された SPN を所有サービス アカウントに軸を変える。そのパスワードをローテーション。日単位ではなく時間単位で解読されたハッシュをリセット。

## Sigma

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

`filter_machine` は (常に `$` で終わる) コンピューター アカウント SPN を除外します。Kerberoasting はユーザー アカウント SPN のみを標的にします。

## KQL と Splunk

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

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## ATT&CK マッピング

- T1558.003 Kerberoasting。見出し。
- T1558.001 Golden Ticket。同じ `LogonGuid` の 4768 なしの 4769。
- T1558.002 Silver Ticket。ターゲット上で観測されたサービス認証に 4769 がない。
- T1078 Valid Accounts。既知のサービス アカウントに対する予期しない IP からの 4769。
- T1550.003 Pass the Ticket。`LogonProcessName: Kerberos` を持つ [4624](/ja/blog/understanding-event-id-4624) LogonType 3 が続く 4769。

## 見ることになる誤検知

- レガシー アプリケーション (一部の古い SQL Server コネクタ、特定の Java/JBoss アプリ) は明示的に RC4 を要求します。安定したホスト群からの安定した日中の 0x17。ベースライン化して除外。
- Kerberos 強化移行中の AES 前ドメインは、すべてのアカウントで `msDS-SupportedEncryptionTypes` が設定されるまで 0x17 を広く出します。煩わしい。悪意はない。
- 脆弱性スキャナー (Tenable、Qualys、BloodHound 列挙スクリプト) は kerberoasting トラフィックを複製します。スキャナー ホストにタグを。
- クロス フォレスト移動中のアカウント移行ツールは、異常な組み合わせを要求することがあります。

シグナルは*バースト*パターンで、個々のレコードではありません。1 つのホストからの安定した 0x17 は構成。数分以内に多数の SPN への 1 つのホストからのバーストな 0x17 が攻撃です。

## 4769 が教えないこと

レコードには暗号化チケット自体は含まれません。解読は攻撃者がエクスフィルした内容に対して起きるのであり、DC からのワイヤ上ではありません。4769 単独からは、「チケットが発行されて未使用」と「チケットが解読され、資格情報が再利用された」を区別できません。チェーンの後半には、ターゲット サービス上の結果の [4624](/ja/blog/understanding-event-id-4624) (LogonType 3、AuthenticationPackage Kerberos) と、理想的には資格情報再利用後に何が動いたかを示す [4688](/ja/blog/event-id-4688-process-creation) または [Sysmon 1](/ja/blog/sysmon-event-id-1-process-create) が必要です。4769 はカナリアであって、警報ではありません。

## タイムラインでの 4769 の位置

古典的なエクスプロイト後 kerberoasting チェーン:

1. ワークステーション上の [4624](/ja/blog/understanding-event-id-4624)。フィッシングされたユーザー資格情報経由の初期アクセス。
2. **4769** ×N、そのワークステーションから 1 つの DC へ、すべて `etype=0x17`、すべて 5 分以内にユーザー SPN サービス アカウントを標的とする。Kerberoasting。
3. *(オフライン、不可視)*。攻撃者が最弱のサービス アカウントのハッシュを Hashcat で解読。
4. [4768](/ja/blog/event-id-4768-kerberos-tgt)。別のホストから、侵害されたサービス アカウントとしての TGT リクエスト。
5. 高価値サーバー上の 4624 LogonType 3、AuthenticationPackage Kerberos。
6. [7045](/ja/blog/service-creation-event-id-7045)。侵害されたアカウントでの永続化のためにインストールされたサービス。

ステップ 2 の 4769 バーストが、最も早く最も安価な検知点です。攻撃者がサービス アカウントとして戻ってくる数時間または数日前。

## 参考資料

- [4769 の Microsoft ドキュメント](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Sean Metcalf: Kerberoasting Without Mimikatz](https://adsecurity.org/?p=2293)

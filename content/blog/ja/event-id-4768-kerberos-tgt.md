---
title: "Event ID 4768 を解説: Kerberos TGT リクエストと AS-REP roasting"
description: "4768 は DC が発行したすべての TGT の記録です。結果コードと pre-auth フラグで読めば、AS-REP roasting、ブルートフォース、unconstrained delegation の悪用を見つけられます。"
date: "2026-05-24"
---

Event ID **4768**「Kerberos 認証チケット (TGT) が要求されました」は、誰かがチケット保証チケットを要求するたびにドメイン コントローラー上で発火します。すべてのドメイン ログオンはこれで始まります。[4769](/ja/blog/event-id-4769-kerberoasting) (サービス チケット) と組み合わせれば、フォレスト内のすべてのアカウントの Kerberos ライフサイクル全体が見えます。

DC では、4768 は [Security チャネル](/ja/blog/what-is-an-evtx-file) で 4624 に次いで最も大量のレコードです。そのほとんどはノイズです。高シグナルなスライスは 2 つの特定のフィールドに住んでおり、その 1 つは AS-REP roasting のフィンガープリントです。

## どこで発火するか

[4769](/ja/blog/event-id-4769-kerberoasting) と同様、4768 は発行**ドメイン コントローラー**にのみ届きます。クライアントは見ません。対象サービスも見ません。4768 から何かを検出するには、すべての DC からの Security 収集が必要です。1 回きりのエンゲージメントなら KAPE スタイル、定常状態なら WEF。

## レコードの中身

```xml
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetSid">S-1-5-21-...-1107</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="ServiceSid">S-1-5-21-...-502</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="PreAuthType">2</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">52814</Data>
<Data Name="CertIssuerName">-</Data>
<Data Name="CertSerialNumber">-</Data>
<Data Name="CertThumbprint">-</Data>
```

重要なフィールド:

- `TargetUserName`。TGT を要求するアカウント。常にユーザーまたはコンピューター アカウント。`ServiceName` は常に `krbtgt`。
- `Status`。Kerberos の結果コード。`0x0` は成功。4768 を有用にするのは失敗です。`0x6` unknown user、`0x12` client locked out、`0x17` password expired、`0x18` bad password。
- `TicketEncryptionType`。4769 と同じエンコーディング: `0x12` と `0x11` AES (最新)、**`0x17` RC4** (レガシー、AS-REP roasting のフィンガープリントでもある)。
- `PreAuthType`。`2` は標準の暗号化タイムスタンプ pre-auth。`0` は**pre-auth が使われなかった**ことを意味します (AS-REP roasting の前提)。`15`、`16`、`17` は PKINIT 証明書ベースの pre-auth 値です。
- `IpAddress`。要求元ホスト。完全なコンテキストには、クライアント側の [4624](/ja/blog/understanding-event-id-4624) と組み合わせてください。
- `CertIssuerName`、`CertSerialNumber`、`CertThumbprint`。PKINIT (スマート カードまたは証明書ログオン) のときに設定されます。パスワード ベース ログオンでは空。

## 4768 が明かす 2 つの攻撃パターン

### AS-REP roasting (T1558.004)

メインの用途。一部のアカウントは `userAccountControl` で `DONT_REQUIRE_PREAUTH` を持ちます (UAC bit 22 = `0x400000`)。そのようなアカウントについて、DC は暗号化タイムスタンプ pre-auth を必要と**せず**に TGT リクエストに応答します。返される AS-REP には、攻撃者がオフラインで解読してアカウントのパスワード ハッシュを回復できる材料が含まれます。

進行中の AS-REP roast の 4768 フィンガープリント:

- `PreAuthType = 0` (pre-auth なし)。
- `TicketEncryptionType = 0x17` (RC4、クラッキング ツールが必要とするもの)。
- `Status = 0x0` (DC は喜んで AS-REP を発行した)。
- しばしばクラスタ化。攻撃者は、どのアカウントが pre-auth 無効化されているかを試すために数十のアカウントをまとめます。

`DONT_REQUIRE_PREAUTH` を持つ実アカウントは、ほぼ排他的にレガシー互換性のために存在します: 非常に古い Unix Kerberos クライアント、一部の古いアプライアンス。数は少なく場所も予測可能です。pre-auth なし Kerberos を使う必要のないアカウントに対する `PreAuthType=0` の 4768 がシグナルです。

### パスワード ブルートフォースまたはスプレー

失敗した Kerberos pre-auth は `Status=0x18` (「パスワード違い」) の 4768 を生成します。[4625](/ja/blog/detecting-4625-brute-force) (NTLM 失敗をキャプチャ) と異なり、4768 は Kerberos ベースのパスワード攻撃の到着点です。最新のツールキット (Rubeus、kerbrute) は Kerberos を直接話します。DC は NTLM 試行で Kerberos 応答よりも速く静かに失敗し、多くの SOC は 4625 しか見ていないからです。

4768 のブルートフォース フィンガープリント:

- 同じ送信元 IP から、短い時間枠内で、同じ `TargetUserName` に対する多数の `Status=0x18` レコード。ブルートフォース。
- 1 つの送信元 IP から、多数の `TargetUserName` 値にわたる多数の `Status=0x18` レコードで、それぞれ 1 〜 2 回ヒット。パスワード スプレー。
- 同じ送信元からの `Status=0x6` (「不明なユーザー」) のバーストが `Status=0x18` に先行。ブルートが始まる前にユーザー列挙が確認された。

## トリアージを駆動するステータス コード

| Status | 意味 | フィールドの読み方 |
|---|---|---|
| `0x0` | KDC_ERR_NONE | 成功。 |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | ユーザー名が存在しない。バースト = 列挙。 |
| `0x12` | KDC_ERR_CLIENT_REVOKED | アカウントがロック、無効、または期限切れ。 |
| `0x17` | KDC_ERR_KEY_EXPIRED | パスワードが期限切れ。 |
| `0x18` | KDC_ERR_PREAUTH_FAILED | パスワード違い。バースト = ブルートフォースまたはスプレー。 |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | 新しい TGT リクエストでクライアントに最初に返される。真の成功が続く。これ単独ではアラートしない。 |
| `0x25` | KRB_AP_ERR_SKEW | 時刻ずれ > 5 分。意図的に時計をずらしたホストからの AS-REP roasting 試行でよくある。 |

## トリアージ ワークフロー: AS-REP roasting

1. すべての DC で `PreAuthType == 0` AND `TicketEncryptionType == 0x17` の 4768 をフィルタ。
2. `IpAddress` でグループ化。既知の移行ホストからの単一アカウントは構成。1 つの送信元からの複数アカウントが攻撃。
3. 各 `TargetUserName` を `userAccountControl` に軸を変える。`DONT_REQUIRE_PREAUTH` は実際に設定する必要があるか? ほぼ確実にない。
4. 攻撃を起動するために認証された資格情報を見つけるため、送信元 IP をそのホスト上の [4624](/ja/blog/understanding-event-id-4624) に軸を変える。
5. 解読されたすべてのアカウントのパスワードをローテーション。必要のないアカウントから `DONT_REQUIRE_PREAUTH` を削除。

## トリアージ ワークフロー: Kerberos ブルートフォース

1. `Status == 0x18` の 4768 をフィルタ。
2. 15 分ウィンドウで `IpAddress` でグループ化。distinct `TargetUserName` を数える。
3. 15 分で 1 つの送信元から 5 アカウント超はスプレー。同じウィンドウで 1 アカウントに対して 10 回超の失敗はブルートフォース。
4. 同じ送信元からの `Status == 0x6` と相互チェック。ブルート前の列挙が教科書的な順序。

## Sigma: AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption. The AS-REP roasting fingerprint.
references:
  - https://attack.mitre.org/techniques/T1558/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  condition: selection
falsepositives:
  - Legacy Unix Kerberos clients explicitly configured without pre-auth
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL: Kerberos パスワード スプレー

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk: AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## ATT&CK マッピング

- T1558.004 AS-REP Roasting。`PreAuthType=0 + etype=0x17` の見出し検知。
- T1110 Brute Force とサブテクニック `.001` Password Guessing と `.003` Password Spraying。`Status=0x18` のパターン。
- T1558.001 Golden Ticket。偽造 TGT は 4768 を完全にバイパスします。検知は*不在*によります: 同じ送信元とウィンドウの先行 4768 がない [4769](/ja/blog/event-id-4769-kerberoasting) が疑いです。
- T1187 Forced Authentication。4768 では直接見えませんが、結果として生じる TGT リクエストでは見えます。

## 攻撃に見える誤検知

- レガシー アプリ サイロの古い Java や Unix Kerberos スタックは、pre-auth なしで RC4 をデフォルトにすることがあります。安定したホストからの安定した、日中の 4768 トラフィックとして現れます。ベースライン化。
- スマート カード展開中の PKINIT 移行。正当な `PreAuthType=15/16/17` の切り替えは、見たことがないと異常に見えます。展開ウィンドウに注意。
- Kerberos ライブラリのバグ。時刻ずれで積極的に TGT を再要求するクライアントがあり、ノイズを生みます。`Status=0x25` で相互チェック。
- ドメイン信頼の通過。クロス フォレスト認証は両側で 4768 を生成します。`IpAddress` は他フォレストの DC です。タグを。

## 4768 が教えないこと

レコードには、攻撃者がキャプチャした実際の AS-REP 材料 (彼らがオフラインで解読するもの) は含まれません。リクエストが発行されたことは見えます。メタデータを超えて何が返されたかは見えません。クライアントの視点も見えません: どのアプリケーションがリクエストを起動したか、どのユーザー コンテキストで実行されたか。それにはクライアント側の [4624](/ja/blog/understanding-event-id-4624) と、`kerbrute.exe` または Rubeus がローカル実行された場合の [4688](/ja/blog/event-id-4688-process-creation) が必要です。

4768 が初回 TGT リクエストと更新でのみ発火することにも注意してください。クライアントが有効な TGT をキャッシュしている限り、更新まで KDC と TGT について話しません。そこから派生するサービス チケットは 4768 ではなく [4769](/ja/blog/event-id-4769-kerberoasting) を生成します。長寿命の TGT を盗む攻撃者 (golden ticket) は、別の 4768 を生成せずに任意の 4769 を発行できます。

## タイムラインでの 4768 の位置

AS-REP roasting の開始から終わり:

1. [4624](/ja/blog/understanding-event-id-4624)。初期低特権ドメイン ログオン (フィッシングされた資格情報)。
2. *(LDAP、SACL が設定されていれば 4662 のこともある)*。攻撃者が `DONT_REQUIRE_PREAUTH` を持つアカウントの `userAccountControl` を列挙。
3. **4768** バースト。`PreAuthType=0`、`etype=0x17`、各候補アカウントの `Status=0x0`。検知点。
4. *(オフライン、不可視)*。攻撃者が回復した AS-REP 材料を Hashcat (モード 18200) で解読。
5. **4768**。今回は通常 pre-auth された、侵害されたアカウントとしての新規 TGT リクエスト。
6. [4769](/ja/blog/event-id-4769-kerberoasting)。侵害されたアカウントが到達できるすべてのサービス チケット。
7. ターゲット サービス上の [4624](/ja/blog/understanding-event-id-4624) LogonType 3。

ステップ 3 がカナリアです。ステップ 5 以降が実際の侵害です。その間のウィンドウは数分から数日で、防御側が資格情報がワイルドで生きている前に対応できる唯一のウィンドウです。

## 参考資料

- [4768 の Microsoft ドキュメント](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)
- [Sean Metcalf: AS-REP Roasting](https://adsecurity.org/?p=3293)

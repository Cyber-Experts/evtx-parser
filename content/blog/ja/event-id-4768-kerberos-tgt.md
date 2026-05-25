---
title: "Event ID 4768 を解読する:Kerberos TGT 要求と AS-REP roasting"
description: "4768 は DC が発行する各 TGT のレコード。結果コードと事前認証フラグで読めば、AS-REP roasting、ブルートフォース、無制約委任の悪用を発見できる。"
date: "2026-05-24"
---

Event ID **4768** — 「Kerberos 認証チケット（TGT）が要求されました」 — は、誰かが Ticket Granting Ticket を要求するたびにドメイン コントローラで発火します。すべてのドメイン ログオンはこのいずれかから始まります。[4769](/ja/blog/event-id-4769-kerberoasting)（サービス チケット）と組み合わせれば、フォレスト内すべてのアカウントの Kerberos ライフサイクル全体が見えます。

DC では 4768 は 4624 に次ぐ高ボリュームの [Security チャネル](/ja/blog/what-is-an-evtx-file) レコードです。大半はノイズで、高シグナルのスライスは 2 つの特定フィールドにあります — そのうち 1 つが AS-REP roasting の指紋です。

## どこで発火するか

[4769](/ja/blog/event-id-4769-kerberoasting) と同様、4768 は発行**ドメイン コントローラ**のみに着地します。クライアントには見えず、ターゲット サービスにも見えません。4768 から何かを検知するには、すべての DC からの Security 収集が必要です — 単発調査なら KAPE スタイル、定常運用なら WEF。

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

重要なフィールド。

- **`TargetUserName`** — TGT を要求しているアカウント。常にユーザーまたはコンピュータ アカウント。`ServiceName` は常に `krbtgt`。
- **`Status`** — Kerberos 結果コード。`0x0` は成功。4768 を有用にするのは失敗:`0x6` = 未知ユーザー、`0x12` = クライアント ロックアウト、`0x17` = パスワード期限切れ、`0x18` = パスワード違い。
- **`TicketEncryptionType`** — 4769 と同じエンコーディング:`0x12`/`0x11` AES（モダン）、**`0x17` RC4**（レガシー、かつ AS-REP roasting の指紋）。
- **`PreAuthType`** — `2` は標準のタイムスタンプ暗号化事前認証、`0` は**事前認証なし**（AS-REP roasting の前提）、`15`/`16`/`17` は PKINIT 証明書ベースの事前認証値。
- **`IpAddress`** — 要求ホスト。完全な文脈にはクライアント側の [4624](/ja/blog/understanding-event-id-4624) と組み合わせ。
- **`CertIssuerName` / `CertSerialNumber` / `CertThumbprint`** — PKINIT（スマートカード / 証明書ログオン）時に充填。パスワード ベースのログオンでは空。

## 4768 が明かす 2 つの攻撃パターン

### 1. AS-REP roasting（T1558.004）

目玉の使い方。一部のアカウントは `userAccountControl` に `DONT_REQUIRE_PREAUTH` フラグが設定されています（UAC ビット 22 = `0x400000`）。それらのアカウントに対して、DC はタイムスタンプ暗号化事前認証を要求**せずに**TGT 要求に応答します — つまり返される AS-REP には、攻撃者がオフラインでクラックしてアカウントのパスワード ハッシュを復元できる素材が含まれます。

進行中の AS-REP roast の 4768 指紋。

- `PreAuthType` が `0`（事前認証なし）。
- `TicketEncryptionType` が `0x17`（RC4 — クラッキング ツールが必要とするもの）。
- `Status` が `0x0`（DC が喜んで AS-REP を発行）。
- しばしばクラスタ化:攻撃者は事前認証無効化されたアカウントを試すため数十アカウントをバッチします。

`DONT_REQUIRE_PREAUTH` が設定されている実アカウントは、ほぼ例外なくレガシー互換性のため（非常に古い Unix Kerberos クライアント、一部の古いアプライアンス）に存在します。数は少なく、場所は予測可能です。事前認証なし Kerberos を*使う理由がない*アカウントに対する `PreAuthType=0` の 4768 がシグナルです。

### 2. パスワード ベースのブルートフォース / スプレー

失敗した Kerberos 事前認証は `Status=0x18`（「パスワード違い」）の 4768 を生成します。[4625](/ja/blog/detecting-4625-brute-force)（NTLM 失敗を捕捉）と違い、Kerberos ベースのパスワード攻撃が着地するのはこの 4768 です。モダンなツールキット（Rubeus、kerbrute）は直接 Kerberos を話します。DC は Kerberos より NTLM のほうが静かに失敗するのが速く、多くの SOC は 4625 しか監視していないためです。

4768 のブルートフォース指紋。

- 同じ送信元 IP から同じ `TargetUserName` への `Status=0x18` レコードが短時間に多数 — 古典的ブルートフォース。
- 同じ送信元 IP から多数の `TargetUserName` 値への `Status=0x18` レコード、各アカウント 1〜2 回ヒット — パスワード スプレー。
- 同じ送信元からの `Status=0x18` に先行する `Status=0x6`（「未知ユーザー」）のバースト — ブルート開始前にユーザー列挙が確認できる。

## 見える Status コード

完全リストは大きいですが、トリアージを駆動するのはこれら。

| Status | 意味 | 実環境での通常意味 |
|---|---|---|
| `0x0` | KDC_ERR_NONE | 成功。 |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | ユーザー名が存在しない。バースト = 列挙。 |
| `0x12` | KDC_ERR_CLIENT_REVOKED | アカウント ロック / 無効 / 期限切れ。 |
| `0x17` | KDC_ERR_KEY_EXPIRED | パスワード期限切れ。 |
| `0x18` | KDC_ERR_PREAUTH_FAILED | パスワード違い。バースト = ブルートまたはスプレー。 |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | 新規 TGT 要求時にまずクライアントに返される。実際の成功はその後に続く。これだけでアラートしない。 |
| `0x25` | KRB_AP_ERR_SKEW | クライアントと DC のクロック スキューが 5 分超。故意にクロックを狂わせたホストからの AS-REP roasting 試行が多い。 |

## トリアージ ワークフロー — AS-REP roasting

1. すべての DC で 4768 を `PreAuthType == 0` かつ `TicketEncryptionType == 0x17` でフィルタ。
2. `IpAddress` でグルーピング。既知の移行ホストからの単一アカウントは設定、1 つの送信元からの複数アカウントは攻撃。
3. 各 `TargetUserName` を `userAccountControl` にピボット — `DONT_REQUIRE_PREAUTH` が本当に必要？ほぼ確実に不要です。
4. 送信元 IP → そのホストの [4624](/ja/blog/understanding-event-id-4624) で、攻撃を起動するために認証した資格情報を見つける。
5. クラックされたアカウントのパスワードをすべてローテーション。必要のないアカウントから `DONT_REQUIRE_PREAUTH` を削除。

## トリアージ ワークフロー — Kerberos ブルートフォース

1. 4768 を `Status == 0x18` でフィルタ。
2. 15 分ウィンドウで `IpAddress` ごとにグルーピング。distinct な `TargetUserName` をカウント。
3. 15 分で 1 つの送信元から 5 を超えるアカウントはスプレー。同ウィンドウで 1 アカウントに対する 10 を超える失敗はブルートフォース。
4. 同じ送信元からの `Status == 0x6` とクロスチェック — ブルート前の列挙は教科書的な順序。

## サンプル Sigma ルール — AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption — the AS-REP roasting fingerprint.
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
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (should be a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## サンプル KQL — Kerberos パスワード スプレー

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## サンプル Splunk — AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## ATT&CK マッピング

- **T1558.004 — AS-REP Roasting**:`PreAuthType=0 + etype=0x17` 上の目玉検知。
- **T1110 — Brute Force** とサブ技法 `.001` Password Guessing と `.003` Password Spraying — `Status=0x18` パターン。
- **T1558.001 — Golden Ticket**:偽造 TGT は 4768 を完全にバイパス。ここでの検知は*不在による* — 同じ送信元 / ウィンドウからの 4768 がない [4769](/ja/blog/event-id-4769-kerberoasting)（TGS 要求）が疑惑。
- **T1187 — Forced Authentication**:4768 では直接見えないが、結果として生じる TGT 要求は見えます。

## 攻撃に見える誤検知

- レガシー アプリ サイロにある**古い Java / Unix Kerberos スタック**は、事前認証なしの RC4 をデフォルトとすることがあります。安定したホストからの定常的な日中 4768 トラフィックとして現れます。ベースライン化。
- スマートカード展開中の **PKINIT 移行**:正当な `PreAuthType=15/16/17` のフリップは見たことがなければ異常に見えます。展開ウィンドウを監視。
- **Kerberos ライブラリのバグ**:一部クライアントは時刻スキューで TGT を積極的に再要求しノイズを生成。`Status=0x25` とクロスチェック。
- **ドメイン トラスト トラバーサル**:クロスフォレスト認証は両側で 4768 を生成。`IpAddress` は別フォレストの DC。タグを付ける。

## 4768 では分からないこと

レコードには、攻撃者がキャプチャした実際の AS-REP 素材（オフラインでクラックするもの）は**含まれません**。要求が発行されたことは見えますが、メタデータ以外に返されたデータは見えません。また、*クライアント*視点 — どのアプリケーションが要求を起動したか、どのユーザー コンテキストで動いていたか — も見えません。それにはクライアント側の [4624](/ja/blog/understanding-event-id-4624)（および `kerbrute.exe` がローカル実行なら [4688](/ja/blog/event-id-4688-process-creation)）が必要です。

また 4768 は*初回*の TGT 要求と更新時のみ発火することに注意してください。一度クライアントが有効な TGT をキャッシュすれば、更新までは KDC とは話しません。そこから派生する*サービス*チケットは [4769](/ja/blog/event-id-4769-kerberoasting) を生成し、4768 ではありません。2 つのレコードは同じプロトコルの異なるステージを記述します — そして長寿命の TGT（ゴールデン チケット）を盗んだ攻撃者は、4768 を二度と生まずに任意の 4769 を発行できます。

## タイムラインにおける 4768 の位置

AS-REP roasting 連鎖、開始から終了まで。

1. [**4624**](/ja/blog/understanding-event-id-4624) — 初期低特権ドメイン ログオン（フィッシングされた資格情報）。
2. *(LDAP、SACL 設定があれば 4662)* — 攻撃者は `DONT_REQUIRE_PREAUTH` を持つアカウントの `userAccountControl` フラグを列挙。
3. **4768** バースト — 候補アカウントごとに `PreAuthType=0`、`etype=0x17`、`Status=0x0`。**ここが検知点。**
4. *(オフライン、不可視)* — 攻撃者は復元した AS-REP 素材を Hashcat（モード 18200）でクラックし平文パスワードを復元。
5. **4768** — 侵害アカウントとして新規 TGT 要求、今度は通常通り事前認証あり。
6. [**4769**](/ja/blog/event-id-4769-kerberoasting) — 侵害アカウントが到達可能なすべての対象に対するサービス チケット。
7. ターゲット サービス上の [**4624**](/ja/blog/understanding-event-id-4624) LogonType 3。

ステップ 3 がカナリア。ステップ 5 以降が実際の侵害。両者の間のウィンドウ — 数分から数日 — が、資格情報が野生で生きる前にディフェンダーが行動できる唯一のウィンドウです。

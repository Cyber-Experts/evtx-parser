---
title: "Windows イベント ID 4624:成功したログオンを解読する"
description: "4624 レコードに実際に何が入っているのか、なぜ LogonType フィールドがイベント自体より重要なのか、トリアージで注目すべきフィールド、そして大量のレコードをフォレンジックで効率よく読み解くための実用的なヒント。"
date: "2026-05-17"
---

イベント ID 4624 — 「アカウントが正常にログオンしました」 — は、Windows が ID を認証するたびに [`Security` チャネル](/ja/blog/what-is-an-evtx-file) に記録されます。ほとんどのワークステーションで最も件数が多いレコードで、ほぼすべての IR 調査の背骨です。これを読めることは必須スキルです。

## 4624 レコードの中身

重要な情報は `<EventData>` の中にあります。

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">LAPTOP-01</Data>
<Data Name="IpAddress">10.0.0.42</Data>
<Data Name="LogonGuid">{...}</Data>
```

`Subject*` 系のフィールドは、ログオンを*要求した*セキュリティ コンテキスト(サービス起動時の `S-1-5-18` = SYSTEM が典型)。`Target*` 系のフィールドが、実際に認証された ID です。これらを混同するとアナリストは何時間も無駄にします。

## 重要なのは LogonType フィールド

Windows には 10 種類のログオンタイプがありますが、トリアージで実際に効くのはごく一部です。

- **2 — Interactive**:物理またはコンソール ログオン。
- **3 — Network**:SMB、RPC、WinRM、ネットワーク経由のあらゆるもの。通常トラフィックの大半。
- **4 — Batch**:ユーザー アカウントで動作するスケジュールド タスク。
- **5 — Service**:特定アカウントで起動されたサービス。
- **7 — Unlock**:スクリーン ロック解除。
- **8 — NetworkCleartext**:稀かつ怪しい — 平文での資格情報伝送(IIS の Basic 認証、古いプリンタなど)。
- **9 — NewCredentials**:`runas /netonly`。攻撃者がローカル権限しか持たないホストにドメイン資格情報を持ち込む際によく使われます。
- **10 — RemoteInteractive**:RDP。`IpAddress` と組み合わせて送信元を特定します。
- **11 — CachedInteractive**:キャッシュ資格情報での ドメイン アカウント ログオン(DC が到達不能)。

日曜の午前 3 時に外部 IP から LogonType **10** の 4624 が来るのと、午前 2 時にバックアップ サーバーから LogonType **3** が 50 件来るのとでは、まったく違う物語です。

## どれと連鎖させるか

成功した 4624 単独では発見になりません。次と組み合わせるとそうなります。

- 同じ送信元からの [**4625**](/ja/blog/detecting-4625-brute-force) が先行 — 失敗の連続後の成功は、ブルートフォース成功の教科書的シグネチャ。
- [**4672**](/ja/blog/event-id-4672-special-privileges)(特権が割り当てられた)— `SeDebugPrivilege` などの特権を付与したログオンを示し、特権アカウント利用の発見に有用。
- **4648**(明示的な資格情報によるログオン)— `runas` その他の資格情報受け渡しパターンを捕捉。

## 大量レコードの読み方

このページのパーサーはレコードの XML から上記のフィールドを直接抽出してテーブルに表示します。タイムラインのバケットとテキスト フィルタ(検索欄に `4624`)で `LogonType` 別に絞り込み、絞り込み結果を CSV エクスポートし、お好みのツールで `SubjectUserSid` + `IpAddress` でピボットしてください。各レコードの完全な XML はワンクリックで表示できます。

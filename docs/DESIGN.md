# DESIGN

## 1. 目的

`discord-oidc` は、Discord を upstream identity source として利用する community-scoped OpenID Connect Provider です。

主目的は、各アプリケーションが Discord OAuth2 を個別実装する構成を避け、Discord community の member identity を標準 OIDC 境界へ正規化することです。

```text
Discord
   │ OAuth2
   ▼
discord-oidc
   │ OIDC
   ├──────────────┬───────────────┐
   ▼              ▼               ▼
Client A       Client B        Client C
```

この Provider は特定アプリケーション専用ではありません。

**1 deployment = 1 community / identity realm** を基本とし、その deployment に複数の OIDC Client を登録します。

---

## 2. 設計原則

### 2.1 Identity realm と Relying Party を分離する

OIDC Provider の deployment unit は利用アプリケーションではなく community です。

悪い例:

```text
CommunityToken 専用 Provider
Dashboard 専用 Provider
Wiki 専用 Provider
```

推奨:

```text
1 Discord community
      │
      ▼
1 OIDC issuer
      │
      ├ CommunityToken
      ├ Dashboard
      └ Wiki
```

同じ Discord user はすべての client で同じ `(iss, sub)` を持ち、`aud` のみ client ごとに変化します。

### 2.2 Canonical identity は `(iss, sub)`

Relying Party が永続 identity として利用する値は次の組です。

```text
issuer  = ID Token `iss`
subject = ID Token `sub`
```

Discord-backed issuer では `sub` に stable Discord user ID (Snowflake) を使用します。

次の値は canonical identity として使用しません。

- email
- username
- display name
- avatar
- Guild role
- Guild nickname

これらは変更可能、非一意、または authorization/context に属する情報です。

### 2.3 Issuer URL は deployment configuration

issuer hostname はコードへ固定しません。

```env
OIDC_ISSUER_URL=https://discord.id.ojiverse.example
```

`OIDC_ISSUER_URL` には任意の stable HTTPS URL を指定できます。

`ojiverse.example` はドキュメント用の予約ドメインです。

一度 production identity binding に利用した issuer URL は長期的な identity namespace として扱います。hostname の変更は cosmetic change ではなく identity migration です。

### 2.4 Cloudflare は runtime、OIDC は contract

実装は Cloudflare 上で動かしますが、Relying Party との契約は標準 OIDC over HTTPS です。

同一 Cloudflare Account 上に client service が存在しても、以下へ依存させません。

- Service Binding を認証契約として利用すること
- shared Durable Object
- shared database
- shared secret による implicit trust

---

## 3. Community admission policy

各 deployment には対象 Discord Guild を 1 つ設定します。

```env
DISCORD_REQUIRED_GUILD_ID=123456789012345678
```

OIDC authentication を完了するには、Discord OAuth2 で認証された user がこの Guild の member である必要があります。

```text
Discord authentication
        │
        ▼
Discord user identity
        │
        ▼
required Guild membership check
        │
    ┌───┴────┐
 member    non-member
    │           │
    ▼           ▼
 continue      deny
```

Guild membership は issuer への admission condition です。

Guild role は canonical identity ではありません。必要であれば追加 claim として提供できますが、role change により `sub` が変化してはいけません。

### 3.1 Guild membership verification

初期実装では Discord OAuth scope として少なくとも以下を想定します。

```text
identify
guilds
```

`GET /users/@me` で user identity を取得し、`GET /users/@me/guilds` の結果から required Guild membership を検証します。

Guild 一覧 API が pagination を持つ場合、途中までの結果だけで「所属していない」と判定してはいけません。required Guild が見つかるか、結果を最後まで検証する必要があります。

role claim 等で Bot API が必要になった場合は別途 Bot Token を導入できますが、基本 identity flow のために Bot を必須にはしません。

---

## 4. OIDC Client model

### 4.1 Static client registry

初期実装では Dynamic Client Registration を実装しません。

少数の trusted client を明示的に設定します。

概念例:

```json
[
  {
    "client_id": "communitytoken-client-id",
    "redirect_uris": [
      "https://communitytoken.ojiverse.example/auth/callback"
    ],
    "type": "public"
  },
  {
    "client_id": "server-side-service",
    "redirect_uris": [
      "https://service.ojiverse.example/oidc/callback"
    ],
    "type": "confidential"
  }
]
```

公開設定は例えば次の環境変数へ与えます。

```env
OIDC_CLIENTS_JSON=[...]
```

confidential client secret は通常の環境変数ではなく Cloudflare Worker Secret 等の secret storage を利用します。

### 4.2 Redirect URI

`redirect_uri` は登録値との **完全一致** で検証します。

以下は禁止します。

- prefix match
- wildcard redirect URI
- request から任意 URI を受け入れること

### 4.3 Audience

`aud` を Provider 全体の固定値にはしません。

認証要求元として検証済みの `client_id` を ID Token の audience とします。

```text
Client A:
  iss = https://discord.id.ojiverse.example
  sub = 123456789012345678
  aud = client-a

Client B:
  iss = https://discord.id.ojiverse.example
  sub = 123456789012345678
  aud = client-b
```

初期実装では public subject を採用します。pairwise subject が必要になった場合は別途設計します。

---

## 5. Public OIDC surface

最低限、次の endpoint を提供します。

```text
GET  /.well-known/openid-configuration
GET  /authorize
GET  /oauth/discord/callback
POST /token
GET  /jwks.json
```

必要に応じて追加:

```text
GET /userinfo
```

### 5.1 Discovery document

`/.well-known/openid-configuration` は `OIDC_ISSUER_URL` を基準に endpoint URL を生成します。

少なくとも以下の metadata を公開する想定です。

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`
- `response_types_supported`
- `subject_types_supported`
- `id_token_signing_alg_values_supported`
- `scopes_supported`
- `claims_supported`
- PKCE capability

実際の公開値は実装された機能と一致している必要があります。

---

## 6. Authorization Code Flow

Authorization Code Flow + PKCE (`S256`) を基本とします。

### 6.1 RP -> `/authorize`

Relying Party から例えば以下を受け取ります。

```text
response_type=code
client_id=...
redirect_uri=...
scope=openid ...
state=...
nonce=...
code_challenge=...
code_challenge_method=S256
```

Provider は最初に以下を検証します。

1. `client_id` が登録済み
2. `redirect_uri` が完全一致で allowlist 済み
3. `response_type=code`
4. `openid` scope が存在
5. PKCE parameter が正しい
6. request parameter のサイズ・形式が妥当

検証後、内部 authorization transaction を生成し、Discord OAuth2 authorization endpoint へ redirect します。

### 6.2 Discord OAuth2

Discord 向けに Provider 自身の OAuth `state` を生成します。

この state は Relying Party が与えた `state` と同一値をそのまま upstream へ横流しするものではありません。

内部 transaction には概ね以下を保持します。

```text
authorization_transaction
├ id
├ oidc_client_id
├ redirect_uri
├ requested_scope
├ rp_state
├ nonce
├ code_challenge
├ discord_oauth_state
├ created_at
└ expires_at
```

Discord callback では Provider が生成した upstream `state` を照合します。

### 6.3 Discord callback

Discord authorization code を Discord token endpoint で交換します。

Discord access token は以下の確認のためだけに利用します。

- `/users/@me`
- required Guild membership
- 必要な追加 claim

認証に不要な Discord access / refresh token を長期保存しません。

検証成功後、Provider 自身の authorization code を新規発行します。

Discord から返された authorization code を Relying Party へそのまま渡してはいけません。

### 6.4 Provider authorization code

Provider が発行する authorization code は:

- cryptographically random
- short-lived
- single-use
- client bound
- redirect URI bound
- PKCE challenge bound
- authenticated subject bound

である必要があります。

概念:

```text
authorization_code
├ code_hash
├ client_id
├ redirect_uri
├ subject
├ nonce
├ scope
├ code_challenge
├ created_at
├ expires_at
└ consumed_at
```

callback 完了時、Relying Party へ次のように戻します。

```text
<registered redirect_uri>?code=<provider code>&state=<original rp state>
```

### 6.5 `/token`

Token endpoint は:

1. authorization code を検索
2. expiry を確認
3. 未使用であることを確認
4. client binding を確認
5. redirect URI binding を確認
6. PKCE verifier を確認
7. confidential client の場合は client authentication を確認
8. code を原子的に consume
9. ID Token を発行

します。

code の検証と consume は atomic でなければなりません。

---

## 7. Token model

### 7.1 ID Token

最低限、次の claim を発行します。

```text
iss
sub
aud
iat
exp
nonce   # authorization request に存在する場合
```

例:

```json
{
  "iss": "https://discord.id.ojiverse.example",
  "sub": "123456789012345678",
  "aud": "communitytoken-client-id",
  "iat": 1770000000,
  "exp": 1770000600,
  "nonce": "..."
}
```

追加 claim 候補:

```text
preferred_username
name
picture
```

Guild / role 情報を追加する場合は claim namespace と情報露出範囲を別途定義します。

### 7.2 Access Token / UserInfo

`/userinfo` を提供する場合、Provider 自身が発行した access token のみを受け付けます。

Discord access token を RP へ公開しません。

初期実装で `/userinfo` が不要なら、必要以上の token/state model を先行実装しない方針とします。ただし OIDC/OAuth2 protocol requirement と実際に採用する library の要件を満たす形で最終決定します。

---

## 8. Cloudflare architecture

```text
Internet
   │
   ▼
Cloudflare Worker
   │
   ├ /.well-known/openid-configuration
   ├ /authorize
   ├ /oauth/discord/callback
   ├ /token
   └ /jwks.json
          │
          ▼
AuthorizationState Durable Object
SQLite-backed storage
```

### 8.1 Worker

Worker の責務:

- HTTP routing
- request parsing / validation
- Discord API interaction
- OIDC response construction
- ID Token signing
- configuration validation

### 8.2 Durable Object

SQLite-backed Durable Object は短期 state の強整合性と atomic consume に利用します。

初期構成では deployment 内に 1 つの authorization-state authority を持つ単純なモデルで十分です。

保持対象候補:

```text
authorization_transactions
authorization_codes
access_tokens (userinfo を実装する場合)
```

長期 user database は持ちません。

Discord user profile を identity database として複製することも目的ではありません。

### 8.3 Signing keys

OIDC signing private key は secret として管理します。

概念的な設定:

```text
OIDC_SIGNING_PRIVATE_KEY
OIDC_SIGNING_KEY_ID
```

`/jwks.json` では対応する public key のみ公開します。

key rotation 時には、既発行 token の検証期間を考慮して旧 public key を一定期間 JWKS に残せる設計とします。

private key を Git repository や通常の公開設定へ保存してはいけません。

---

## 9. Configuration model

具体的な変数名は実装過程で変更可能ですが、責務として以下を想定します。

### 9.1 Non-secret

```env
OIDC_ISSUER_URL=https://discord.id.ojiverse.example
DISCORD_CLIENT_ID=...
DISCORD_REQUIRED_GUILD_ID=...
OIDC_CLIENTS_JSON=...
OIDC_SIGNING_KEY_ID=...
```

### 9.2 Secret

```text
DISCORD_CLIENT_SECRET
OIDC_SIGNING_PRIVATE_KEY
OIDC_CLIENT_SECRETS_JSON  # confidential client をサポートする場合
```

### 9.3 `OIDC_ISSUER_URL` validation

少なくとも次を要求します。

- absolute HTTPS URL
- query / fragment を含まない
- discovery document の `issuer` と ID Token の `iss` が完全一致
- request `Host` header から issuer を推測しない

proxy / custom domain の構成ミスによって `iss` が変化してはいけません。

---

## 10. Error handling

OAuth2 / OIDC endpoint では protocol に従った error response を返します。

内部エラー詳細、Discord access token、client secret、authorization code などを user-facing response へ含めません。

ログには correlation/request ID を付与しますが、token や secret を記録しません。

---

## 11. Repository / deployment boundary

`discord-oidc` は Relying Party とは別 repository / deployment とします。

同一 Cloudflare Account へ deploy しても構いませんが、以下を共有前提にしません。

```text
storage
service binding
application session
OIDC client secret
CI/CD credential
```

CI/CD credential は可能な範囲で repository ごとに scope を分離します。

---

## 12. Non-goals

初期設計では以下を対象外とします。

- Dynamic Client Registration
- pairwise subject
- general-purpose IAM / directory service
- password authentication
- local user/password database
- arbitrary social login federation
- Relying Party の user/session database
- application-specific authorization rules
- Discord bot interaction handling

---

## 13. Prior art

本設計は [Erisa/discord-oidc-worker](https://github.com/Erisa/discord-oidc-worker) を参考にしています。

同プロジェクトの「Discord OAuth2 を Cloudflare Worker 上で OIDC として公開する」というアプローチを参考にしつつ、本プロジェクトでは以下を明示的に設計目標とします。

- Cloudflare Access 専用ではない OIDC Provider
- stable configurable issuer
- standard `(iss, sub)` identity
- community / Guild scoped deployment
- one issuer / multiple OIDC clients
- client-specific `aud`
- Provider 自身の authorization code lifecycle
- Relying Party との storage/runtime 非結合

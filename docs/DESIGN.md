# DESIGN

## 1. 目的

`discord-oidc` は、Discord OAuth2 を利用して Discord user を認証し、OpenID Connect (OIDC) の OpenID Provider (OP) として標準 OIDC interface を提供するサービスです。

主目的は、各 Relying Party (RP) が Discord OAuth2 と Discord 固有 API を個別実装する構成を避けることです。

```text
Discord
   │ OAuth2 / API
   ▼
discord-oidc
OpenID Provider
   │ OIDC
   ├──────────────┬───────────────┐
   ▼              ▼               ▼
RP / Client A  RP / Client B   RP / Client C
```

この Provider は特定の RP 専用ではありません。

**1 deployment = 1 configured Discord Guild** を基本とし、その deployment に複数の OIDC Client を登録します。

---

## 2. 設計原則

### 2.1 Discord Guild と Relying Party を分離する

OpenID Provider の deployment は 1 つの Discord Guild に紐付きます。

RP ごとに Provider を複製しません。

避ける構成:

```text
RP A 専用 Provider
RP B 専用 Provider
RP C 専用 Provider
```

推奨構成:

```text
1 Discord Guild
      │
      ▼
1 OpenID Provider / issuer
      │
      ├ RP / Client A
      ├ RP / Client B
      └ RP / Client C
```

同じ Discord user は、public subject を採用している限りすべての OIDC Client で同じ `(iss, sub)` を持ち、`aud` は Client ごとに変化します。

### 2.2 Canonical external identity は `(iss, sub)`

Relying Party が外部主体を永続的に識別する値は次の組です。

```text
issuer  = ID Token `iss`
subject = ID Token `sub`
```

Discord-backed issuer では `sub` に stable Discord user ID (Snowflake) を使用します。

次の値は subject identifier として使用しません。

- email
- username
- display name
- avatar
- Guild role
- Guild nickname

これらは変更可能、非一意、または authorization 用の属性です。

### 2.3 Issuer URL は deployment configuration

issuer hostname はコードへ固定しません。

```env
OIDC_ISSUER_URL=https://discord.id.ojiverse.example
```

`OIDC_ISSUER_URL` には任意の stable HTTPS origin を指定できます。各 endpoint は root の固定 path (`/authorize`, `/token`, `/jwks.json`, `/oauth/discord/callback`) で route されるため、path を含む issuer は受理しません。

`ojiverse.example` はドキュメント用の予約ドメインです。

一度 production の `(iss, sub)` に利用した issuer URL は長期的な issuer identifier として扱います。hostname の変更は cosmetic change ではなく external identity migration です。

### 2.4 Cloudflare は runtime、OIDC は protocol contract

実装は Cloudflare 上で動かしますが、Relying Party との契約は標準 OIDC over HTTPS です。

同一 Cloudflare Account 上に RP が存在しても、以下へ依存させません。

- Service Binding を OIDC authentication の契約として利用すること
- shared Durable Object
- shared database
- shared secret による implicit trust

---

## 3. Discord Guild membership requirement

各 deployment には対象 Discord Guild を 1 つ設定します。

```env
DISCORD_REQUIRED_GUILD_ID=123456789012345678
```

OIDC authentication を完了するには、Discord OAuth2 で認証された user がこの Guild の member である必要があります。

```text
Discord OAuth2 authentication
        │
        ▼
Discord user
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

Guild role は `sub` を構成しません。必要であれば追加 claim として提供できますが、role change によって `sub` が変化してはいけません。

### 3.1 Guild membership verification

初期実装では Discord OAuth scope として少なくとも以下を想定します。

```text
identify
guilds.members.read
```

`GET /users/@me` で Discord user を取得し、`GET /users/@me/guilds/{guild_id}/member` で required Guild への membership を直接照会します。member object が返れば member、404 であれば non-member と判定します。Guild 一覧の走査や pagination の処理は行いません。

API error、rate limit、判定不能な response の場合は fail-open せず authentication を失敗させます。

この endpoint が返す member object には role 情報が含まれるため、将来 Guild role claim を追加する場合も、基本的な authentication flow のために Bot Token は必須としません。

---

## 4. OIDC Client model

### 4.1 Static client registry

初期実装では Dynamic Client Registration を実装しません。

少数の trusted OIDC Client を明示的に設定します。

概念例:

```json
[
  {
    "client_id": "rp-a-client-id",
    "redirect_uris": [
      "https://rp-a.ojiverse.example/auth/callback"
    ],
    "allowed_scopes": ["openid"],
    "type": "public",
    "token_endpoint_auth_method": "none"
  },
  {
    "client_id": "rp-b-client-id",
    "redirect_uris": [
      "https://rp-b.ojiverse.example/oidc/callback"
    ],
    "allowed_scopes": ["openid"],
    "type": "confidential",
    "token_endpoint_auth_method": "client_secret_basic"
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
  aud = rp-a-client-id

Client B:
  iss = https://discord.id.ojiverse.example
  sub = 123456789012345678
  aud = rp-b-client-id
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

`/token` への CORS は有効化しません。browser-based public client をサポートする必要が生じた場合は、登録 client の origin allowlist 方式で個別に設計します。

### 5.1 Discovery document

`/.well-known/openid-configuration` は `OIDC_ISSUER_URL` を基準に endpoint URL を生成します。

少なくとも以下の metadata を公開する想定です。

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`
- `response_types_supported` = `["code"]`
- `grant_types_supported` = `["authorization_code"]`
- `subject_types_supported` = `["public"]`
- `id_token_signing_alg_values_supported` = `["RS256"]`
- `scopes_supported` = `["openid"]`
- `claims_supported`
- `token_endpoint_auth_methods_supported` = `["client_secret_basic", "none"]`
- `code_challenge_methods_supported` = `["S256"]`

公開 metadata は実装された機能と一致している必要があります。

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
5. request された scope のうち client の `allowed_scopes` に含まれない値は無視し、intersection を granted scope とします (RFC 6749 §3.3)。`allowed_scopes` 外の値で fail closed はしません — Cloudflare Access の generic OIDC connector のように `openid email profile` を常に送る client と interoperate するためです。granted scope は token response の `scope` field で client に通知します
6. PKCE parameter が正しい(`code_challenge` は 43–128 文字の base64url、`code_challenge_method=S256`)
7. request parameter のサイズ・形式が妥当

認識しない request parameter は無視します (拡張 parameter を送る client を壊さないため)。ただし OIDC が定義する `prompt` / `max_age` は例外で、黙って無視すると要求された security semantics をすり抜けるため、以下の fail-closed ポリシーを取ります。

- `prompt=none`: silent authentication を成立させる手段 (provider 側 session) がないため `login_required` error を登録 `redirect_uri` へ返し、Discord へは redirect しません
- `prompt=login`: Discord OAuth は再認証を保証しないため `login_required` error を返します。Discord の `prompt=consent` は authorization の再承認であり再認証ではないため、代用には使いません
- `prompt=consent`: Discord authorization request の `prompt=consent` へそのまま対応付けます (consent semantics が一致するため)
- `prompt=select_account`: Discord に account selection 機構がないため `account_selection_required` error を返します
- `prompt=none` と他の値の併用: `invalid_request` error を返します
- 未知の `prompt` 値: 無視します
- `max_age`: 非負整数として検証し、指定された場合は常に `login_required` error を返します。信頼できる upstream authentication time が取得できず、`auth_time` を捏造して成功扱いにはしません

検証後、内部 authorization transaction を生成し、Discord OAuth2 authorization endpoint へ redirect します。

### 6.2 Discord OAuth2

Discord 向けに Provider 自身の OAuth `state` を生成します。

この state は Relying Party が `/authorize` に渡した `state` と同一値をそのまま Discord へ横流しするものではありません。

`discord_oauth_state` は 256 bit の cryptographically random な base64url 値とします。Discord authorization endpoint は `https://discord.com/oauth2/authorize` 固定、要求 scope は `identify guilds.members.read` 固定とします。

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

Discord callback では Provider が生成した `discord_oauth_state` を照合します。

authorization transaction の TTL は 10 分とし、失効した transaction は継続できません。transaction は callback 処理時に consume し、再利用を許しません。

### 6.3 Discord callback

Discord authorization code を Discord token endpoint (`https://discord.com/api/v10/oauth2/token`) で交換します。Discord application の credential は Discord の仕様に従って送信します。

Discord access token は以下の確認のためだけに利用します。

- `GET /users/@me` (Discord user ID の取得)
- `GET /users/@me/guilds/{guild_id}/member` (required Guild membership)

`sub` には `/users/@me` が返す `id` (Snowflake) をそのまま文字列として使用します。

OIDC authentication に不要な Discord access / refresh token を長期保存しません。

Discord が error を返した場合 (例: `access_denied`) や membership 検証に失敗した場合は、transaction に保持した RP の `state` とともに、対応する OIDC error を登録済み `redirect_uri` へ redirect して返します。

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

code は 256 bit の cryptographically random な base64url 値とし、TTL は 60 秒とします。storage には SHA-256 hash (`code_hash`) のみを保存します。

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

1. `grant_type` が `authorization_code` であることを確認
2. confidential client の場合は `client_secret_basic` による client authentication を確認
3. authorization code を検索
4. expiry を確認
5. 未使用であることを確認
6. client binding を確認
7. redirect URI binding を確認
8. PKCE verifier を確認
9. code を原子的に consume
10. ID Token を発行

します。

code の検証と consume は atomic でなければなりません。

request body は `application/x-www-form-urlencoded` とします。public client は `client_id` を body で送信し、code の client binding と照合します。

client authentication の失敗は `401` + `WWW-Authenticate` header と `invalid_client` を返します。grant の検証失敗 (unknown / expired / consumed code、PKCE mismatch、client / redirect URI binding 不一致など) は `400` + `invalid_grant` とし、内部詳細を含めません。

成功 response と error response の両方に `Cache-Control: no-store` と `Pragma: no-cache` を付与します。

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
at_hash # access token とともに発行される場合
```

例:

```json
{
  "iss": "https://discord.id.ojiverse.example",
  "sub": "123456789012345678",
  "aud": "rp-a-client-id",
  "iat": 1770000000,
  "exp": 1770000600,
  "nonce": "..."
}
```

サポートする scope は `openid` のみです。`profile` 等の scope 由来 claim は access token を発行する flow では UserInfo endpoint から返すのが標準 semantics であり、`/userinfo` を実装しない初期実装では ID Token に profile claim を含めません。`email` claim は発行しません。Discord OAuth で `email` scope も要求しません。

token response が返す opaque `access_token` は UserInfo その他の protected resource には紐付けません。

初期実装では Guild / role claim を発行しません。role 情報が必要な Relying Party は Discord API を直接利用します。将来 Provider claim として追加する場合は、claim namespace と情報露出範囲を別途定義します。

`exp` は `iat` から 15 分を初期値とし、運用に応じて調整可能な設定値とします。

### 7.2 Access Token / UserInfo

`/userinfo` を提供する場合、Provider 自身が発行した access token のみを受け付けます。

Discord access token を RP へ公開しません。

token response は `/userinfo` の有無にかかわらず `access_token` を含める必要があります。初期実装で `/userinfo` を提供しない場合は、256 bit の random な opaque access token を発行して仕様を満たします。この token はどの endpoint にも紐付かず storage にも保存しません。追加の token/state model は先行実装しません。

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

Discord user profile を user directory として複製することも目的ではありません。

expired な transaction / code は DO alarm による periodic sweep で削除します。

### 8.3 Signing keys

OIDC signing private key は secret として管理します。

概念的な設定:

```text
OIDC_SIGNING_PRIVATE_KEY
OIDC_SIGNING_KEY_ID
OIDC_JWKS_ADDITIONAL_PUBLIC_KEYS  # rotation 中に公開する旧 public JWK の配列 (optional)
```

署名 algorithm は RS256 とし、Relying Party library との interoperability を優先します。

署名は Cloudflare Workers の Web Crypto API (`crypto.subtle`) で行い、pure-Rust の RSA 実装は private key operation に使用しません（timing side-channel 対策、RUSTSEC-2023-0071 参照）。private key は PKCS#8 の RSA-2048 以上を要求します。

`/jwks.json` では対応する public key のみ公開します。

key rotation 時には、新しい private key で署名を開始し、旧 public key は `OIDC_JWKS_ADDITIONAL_PUBLIC_KEYS` 経由で既発行 token の expiry がすべて過ぎるまで JWKS に残します。旧 private key は保持しません。

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

Discord application には `{OIDC_ISSUER_URL}/oauth/discord/callback` を redirect URI として登録します。

### 9.2 Secret

```text
DISCORD_CLIENT_SECRET
OIDC_SIGNING_PRIVATE_KEY
OIDC_CLIENT_SECRETS_JSON  # confidential client をサポートする場合
```

### 9.3 `OIDC_ISSUER_URL` validation

少なくとも次を要求します。

- absolute HTTPS URL
- userinfo / query / fragment を含まない
- path を含まない（origin のみ。`https://example.com/oidc` のような issuer は拒否する）
- discovery document の `issuer` と ID Token の `iss` が完全一致
- request `Host` header から issuer を推測しない

proxy / custom domain の構成ミスによって `iss` が変化してはいけません。

---

## 10. Error handling

OAuth2 / OIDC endpoint では protocol に従った error response を返します。

`/authorize` では、`client_id` と `redirect_uri` の検証に成功するまではいかなる URI にも redirect せず、error をその場で render します。検証後に発生した error (scope、PKCE、upstream 失敗など) は、登録済み `redirect_uri` へ `error` と受け取った `state` を付けて redirect して返します。

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
- OP 側の login session / Single Sign-On(authorization は毎回 Discord OAuth2 を経由します)
- Refresh token / `offline_access` scope
- `email` claim / Discord `email` scope
- Guild / role claim(Relying Party が必要な場合は Discord API を直接利用します)
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

- Cloudflare Access 専用ではない OpenID Provider
- stable configurable issuer
- standard `(iss, sub)` subject identification
- single Discord Guild per deployment
- one issuer / multiple OIDC clients
- client-specific `aud`
- Provider 自身の authorization code lifecycle
- Relying Party との storage/runtime 非結合

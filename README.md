# discord-oidc

Discord OAuth2 を利用して Discord ユーザーを認証し、OpenID Connect (OIDC) の OpenID Provider (OP) として ID Token を発行する Cloudflare Workers 向けサービスです。

各 deployment は **1 つの Discord Guild** に紐付きます。OIDC authentication を完了できるのは、その Guild の member として確認できた Discord user に限ります。

1 つの deployment には複数の OIDC Client / Relying Party (RP) を登録できます。

> [!IMPORTANT]
> この Provider は Relying Party ごとに deployment するものではありません。
> **1 deployment = 1 configured Discord Guild** とし、その OpenID Provider に複数の OIDC Client を登録することを基本モデルとします。

## Motivation

Discord は OAuth2 を提供していますが、OIDC Provider ではありません。

そのため Discord account を複数の Relying Party から共通して利用しようとすると、各 RP が Discord OAuth2 と Discord 固有 API を個別に実装する必要があります。

`discord-oidc` は Discord OAuth2 / Discord API による認証と Guild membership verification を OpenID Provider 側で処理し、RP には標準 OIDC interface を提供します。

```text
Discord
   │ OAuth2 / API
   ▼
discord-oidc
OpenID Provider
   │ OIDC
   ├───────────────┬────────────────┐
   ▼               ▼                ▼
RP / Client A   RP / Client B    RP / Client C
```

Relying Party が canonical external identity として扱う値は次の組です。

```text
(iss, sub)
```

- `iss`: OpenID Provider の stable issuer URL
- `sub`: Discord の stable user ID (Snowflake)

email、username、display name、Guild role などを subject identifier の代わりに使用しません。

## Discord Guild binding

各 deployment は対象 Discord Guild を 1 つ設定します。

認証時には Discord OAuth2 で user を確認した後、その user が設定済み Guild の member であることを検証します。Guild membership を確認できない場合、OIDC authorization を完了しません。

例えば documentation 用の issuer を次のように設定できます。

```text
https://discord.id.ojiverse.example
```

実際の issuer domain は固定されません。`OIDC_ISSUER_URL` に任意の stable HTTPS URL を指定して利用できる設計とします。

```env
OIDC_ISSUER_URL=https://discord.id.ojiverse.example
DISCORD_REQUIRED_GUILD_ID=123456789012345678
```

`ojiverse.example` は documentation 用の予約ドメインです。

## One issuer, multiple clients

1 つの OpenID Provider deployment に複数の OIDC Client を登録します。

```text
https://discord.id.ojiverse.example
│
├ client: rp-a
├ client: rp-b
└ client: rp-c
```

ID Token の `aud` は Provider 全体の固定値ではなく、authorization request の検証済み `client_id` に応じて決定します。

```json
{
  "iss": "https://discord.id.ojiverse.example",
  "sub": "123456789012345678",
  "aud": "rp-a-client-id"
}
```

別の OIDC Client が認証した場合、public subject を採用している限り `iss` と `sub` は同じまま、`aud` がその Client の `client_id` になります。

初期設計では Dynamic Client Registration は実装せず、明示的な static client registry を利用します。

## Target platform

Cloudflare 上での運用を前提とします。

想定コンポーネント:

- Cloudflare Workers: OIDC / Discord OAuth2 HTTP endpoints
- SQLite-backed Durable Objects: authorization transaction、single-use authorization code、必要な短期 state
- Worker Secrets: Discord client secret、OIDC signing private key、confidential OIDC client secret
- Custom Domain: stable OIDC issuer URL

Cloudflare 固有機能は実装基盤として利用しますが、Relying Party との契約は標準 OIDC over HTTPS とします。

同じ Cloudflare Account 上に RP を配置する場合でも、Service Binding や shared storage を OIDC の信頼境界にはしません。

## Expected OIDC endpoints

少なくとも以下を提供する設計です。

```text
GET  /.well-known/openid-configuration
GET  /authorize
GET  /oauth/discord/callback
POST /token
GET  /jwks.json
```

必要に応じて `/userinfo` を追加します。

Authorization Code Flow + PKCE (`S256`) を基本とします。

## Configuration

具体的な名称は実装時に確定しますが、設定責務は概ね以下を想定しています。

### Public / non-secret configuration

```env
OIDC_ISSUER_URL=https://discord.id.ojiverse.example
DISCORD_CLIENT_ID=...
DISCORD_REQUIRED_GUILD_ID=...
OIDC_CLIENTS_JSON=...
OIDC_SIGNING_KEY_ID=...
```

`OIDC_CLIENTS_JSON` は、少数の trusted OIDC Client を静的に登録する用途です。

例:

```json
[
  {
    "client_id": "rp-a-client-id",
    "redirect_uris": [
      "https://rp-a.ojiverse.example/auth/callback"
    ],
    "allowed_scopes": ["openid", "profile"],
    "type": "public",
    "token_endpoint_auth_method": "none"
  }
]
```

### Secrets

以下は Git に保存しません。

```text
DISCORD_CLIENT_SECRET
OIDC_SIGNING_PRIVATE_KEY
confidential OIDC client secrets (when supported)
```

詳細は [docs/SECURITY.md](./docs/SECURITY.md) を参照してください。

## Identity claims

ID Token は OIDC の標準 claim を中心に構成します。

```text
iss
sub
aud
iat
exp
nonce   # authorization request に存在する場合
```

追加 claim として、次のような情報を提供する余地があります。

```text
preferred_username
name
picture
Guild / role related claims
```

ただし、これらは表示または authorization 用の claim であり、subject identifier の代わりには使用しません。

## Repository scope

このリポジトリが責任を持つもの:

- Discord OAuth2 authorization
- required Discord Guild membership validation
- OpenID Provider endpoints
- OIDC client registry
- authorization code lifecycle
- PKCE validation
- ID Token issuance / signing
- JWKS exposure / signing key rotation strategy

責任を持たないもの:

- Provider 側の login session / Single Sign-On
- Refresh token / `offline_access` の発行
- Relying Party 内部の user database
- application-specific data model
- application-specific authorization policy
- Discord bot interaction handling
- Relying Party の session lifecycle

## Documentation

- [設計](./docs/DESIGN.md)
- [セキュリティ設計](./docs/SECURITY.md)

## Prior art

本プロジェクトの発想・設計検討にあたり、[Erisa/discord-oidc-worker](https://github.com/Erisa/discord-oidc-worker) を参考にしています。

同プロジェクトは Discord OAuth2 を Cloudflare Workers 上で OIDC へ bridge し、Cloudflare Access から Discord identity を利用できるようにする実装です。

`discord-oidc` ではそのアイデアを参考にしつつ、Cloudflare Access 専用ではない OpenID Provider、single-Guild deployment、multiple OIDC clients、client-specific `aud` を明示的に設計します。

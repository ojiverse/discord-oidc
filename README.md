# discord-oidc

Discord を upstream identity source として利用する、Cloudflare Workers 上の community-scoped OpenID Connect Provider です。

このプロジェクトは、特定の Discord Guild に所属するユーザーを OIDC Principal として公開し、複数の OIDC Relying Party から同じ identity realm を利用できるようにすることを目的としています。

> [!IMPORTANT]
> この Provider は用途ごとに 1 インスタンスずつ建てるものではありません。
> **1 deployment = 1 community / identity realm** とし、その配下に複数の OIDC Client を登録することを基本モデルとします。

## Motivation

Discord は OAuth2 を提供していますが、OIDC Provider ではありません。

そのため、Discord アカウントを CommunityToken やその他のサービスから共通の認証基盤として利用しようとすると、各サービスが Discord OAuth2 を個別実装し、Discord 固有の user ID / guild / role といった概念をそれぞれ理解する必要があります。

`discord-oidc` は Discord OAuth2 を OIDC 境界へ正規化します。

```text
Discord
   │ OAuth2
   ▼
discord-oidc
   │ OpenID Connect
   ├───────────────┬────────────────┐
   ▼               ▼                ▼
CommunityToken   Service A        Service B
```

Relying Party から見た canonical identity は常に次の組です。

```text
(iss, sub)
```

- `iss`: この Provider の stable issuer URL
- `sub`: Discord の stable user ID (Snowflake)

email、username、display name、guild role などを identity key として利用しません。

## Community-scoped identity realm

各 deployment は対象 Discord Guild を 1 つ設定します。

認証時には Discord OAuth2 でユーザーを確認した後、そのユーザーが設定済み Guild の member であることを検証します。Guild に所属していないユーザーには OIDC authorization を完了させません。

例えば documentation 用の issuer を次のように設定した場合:

```text
https://discord.id.ojiverse.example
```

この issuer は「特定アプリケーション用の Discord login endpoint」ではなく、「その Discord community の identity realm」を表します。

実際の deployment domain は固定されません。`OIDC_ISSUER_URL` に任意の HTTPS URL を指定して利用できる設計とします。

```env
OIDC_ISSUER_URL=https://discord.id.ojiverse.example
DISCORD_REQUIRED_GUILD_ID=123456789012345678
```

`ojiverse.example` はあくまで documentation 用の予約ドメインです。

## One issuer, multiple clients

1つの Provider deployment に複数の OIDC Client を登録します。

```text
https://discord.id.ojiverse.example
│
├ client: communitytoken
├ client: internal-dashboard
└ client: another-service
```

ID Token の `aud` は固定値ではなく、認証要求元の検証済み `client_id` に応じて発行します。

```json
{
  "iss": "https://discord.id.ojiverse.example",
  "sub": "123456789012345678",
  "aud": "communitytoken-client-id"
}
```

別の client が認証した場合、`iss` と `sub` は同じまま、`aud` がその client の `client_id` になります。

初期設計では Dynamic Client Registration は実装せず、明示的な static client registry を利用します。

## Target platform

Cloudflare 上での運用を前提とします。

想定コンポーネント:

- Cloudflare Workers: OIDC / Discord OAuth2 HTTP endpoints
- SQLite-backed Durable Objects: authorization transaction、single-use authorization code、必要な短期状態
- Worker Secrets: Discord client secret、OIDC signing private key、confidential client secret
- Custom Domain: stable OIDC issuer URL

Cloudflare 固有機能は実装基盤として利用しますが、Relying Party との契約は標準的な OIDC over HTTPS とします。

同じ Cloudflare Account 上に Relying Party を配置する場合でも、Service Binding や共有 storage を OIDC の信頼境界にはしません。

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

`OIDC_CLIENTS_JSON` は、少数の trusted client を静的に登録する用途です。

例:

```json
[
  {
    "client_id": "communitytoken-client-id",
    "redirect_uris": [
      "https://communitytoken.ojiverse.example/auth/callback"
    ],
    "type": "public"
  }
]
```

### Secrets

以下は Git に保存しません。

```text
DISCORD_CLIENT_SECRET
OIDC_SIGNING_PRIVATE_KEY
confidential client secrets (when supported)
```

詳細は [docs/SECURITY.md](./docs/SECURITY.md) を参照してください。

## Identity claims

必須となる identity claims は OIDC の標準 claim を中心にします。

```text
iss
sub
aud
iat
exp
nonce   # authorization request に存在する場合
```

追加情報として、次のような claim を提供する余地があります。

```text
preferred_username
name
picture
guild / role related claims
```

ただし、これらは表示・authorization/context 用であり canonical identity ではありません。

## Repository scope

このリポジトリが責任を持つもの:

- Discord OAuth2 authorization
- required Guild membership validation
- OIDC Provider endpoints
- OIDC client registry
- authorization code lifecycle
- PKCE validation
- ID Token issuance / signing
- JWKS exposure / signing key rotation strategy

責任を持たないもの:

- Relying Party 内部の user database
- CommunityToken の wallet / economy
- application-specific authorization policy
- Discord bot interaction handling
- Relying Party の session lifecycle

## Documentation

- [設計](./docs/DESIGN.md)
- [セキュリティ設計](./docs/SECURITY.md)

## Prior art

本プロジェクトの発想・設計検討にあたり、[Erisa/discord-oidc-worker](https://github.com/Erisa/discord-oidc-worker) を参考にしています。

同プロジェクトは Discord OAuth2 を Cloudflare Workers 上で OIDC へ bridge し、Cloudflare Access から Discord identity を利用できるようにする実装です。

`discord-oidc` ではそのアイデアを参考にしつつ、特定の Cloudflare Access application に限定せず、community-scoped issuer + multiple OIDC clients という用途に合わせて独立した OIDC Provider として設計します。

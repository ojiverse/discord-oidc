# SECURITY

## 1. この文書の目的

`discord-oidc` は認証境界を提供するため、通常の application backend よりも security-sensitive なコンポーネントです。

この文書では、初期設計で想定する脅威、守るべき security invariant、secret / token / authorization code の取り扱い方針を定義します。

実装時には「動くこと」よりも、ここで定義した認証境界が破られないことを優先します。

---

## 2. Trust boundary

概念的な信頼境界は次の通りです。

```text
Browser / Relying Party
        │
        │ OIDC
        ▼
┌──────────────────────────┐
│ discord-oidc             │
│ Cloudflare Worker        │
│                          │
│ OpenID Provider          │
│ AuthorizationState DO    │
└────────────┬─────────────┘
             │ Discord OAuth2/API
             ▼
          Discord
```

`discord-oidc` は以下を信頼します。

- configured Discord OAuth2/API endpoints
- configured Discord application credentials
- configured OIDC client registry
- configured signing key
- configured required Guild ID

Relying Party から渡される値は、登録済み client configuration と照合するまで信頼しません。

同じ Cloudflare Account 内で稼働する別 Worker も、自動的に trusted caller とは見なしません。

---

## 3. Security invariants

最低限、以下を invariant とします。

1. 未登録 client は authorization を開始できない。
2. `redirect_uri` は登録値との完全一致でなければならない。
3. Discord OAuth callback は Provider が発行した upstream state と紐付いていなければならない。
4. Discord user が required Guild member でなければ OIDC authentication を完了しない。
5. Provider authorization code は短命・single-use・client bound である。
6. authorization code と PKCE challenge は同じ authorization transaction に binding される。
7. token endpoint で authorization code を consume する処理は atomic である。
8. ID Token の `iss` は configured `OIDC_ISSUER_URL` と完全一致する。
9. ID Token の `sub` は authenticated Discord user の stable user ID から決定する。
10. ID Token の `aud` は認証要求元として検証済みの OIDC client に対応する。
11. signing private key、Discord client secret、confidential client secret を公開しない。
12. Discord access / refresh token を Relying Party に渡さない。
13. token、authorization code、secret を application log に記録しない。
14. username、email、display name、Guild role を subject identifier の代わりに使用しない。

---

## 4. Threat model

### 4.1 Open redirect / redirect URI substitution

#### Threat

攻撃者が任意の `redirect_uri` を指定し、authorization code を攻撃者管理下へ送信させる。

#### Mitigation

- client ごとに redirect URI allowlist を持つ
- request URI と登録 URI を完全一致で比較する
- wildcard を許可しない
- prefix / suffix match を行わない
- validation 前に redirect しない

不正な `redirect_uri` の場合、エラー情報をその URI へ redirect してはいけません。

`client_id` と `redirect_uri` の検証を通過した後に発生した protocol error は、登録済み `redirect_uri` へ `error` と受け取った `state` を付けて返します。

---

### 4.2 Authorization code interception / replay

#### Threat

authorization code を盗んだ第三者が token endpoint で交換する、または同じ code を複数回交換する。

#### Mitigation

- Authorization Code Flow + PKCE (`S256`)
- code は十分な entropy を持つ cryptographically random value
- storage には plaintext code ではなく hash を保存
- short TTL
- code を client / redirect URI / PKCE challenge に binding
- exchange 時に atomic consume
- consumed code は再利用不可

Durable Object + SQLite transaction によって check-and-consume を一つの atomic operation にします。

---

### 4.3 Login CSRF / upstream OAuth state confusion

#### Threat

別ユーザーの Discord callback や、攻撃者が開始した OAuth transaction を被害者の OIDC transaction へ結び付ける。

#### Mitigation

Provider は Discord OAuth2 用の独自 `state` を生成し、authorization transaction と紐付けます。

Relying Party が Provider `/authorize` に渡した `state` と、Discord upstream に渡す state を同じ未加工値として扱いません。

```text
RP state
   ↓
Provider authorization transaction
   ↑
Provider-generated Discord OAuth state
```

callback では Provider-generated state を照合した後にのみ transaction を継続します。

---

### 4.4 ID Token replay / login response substitution

#### Threat

過去または別 login flow の ID Token を別 session で再利用する。

#### Mitigation

- short `exp`
- 正しい `iat`
- Relying Party から `nonce` が指定された場合は authorization transaction に保持し ID Token へ反映
- RP は `iss` / signature / `aud` / `exp` / `nonce` を検証

Provider 側だけで replay を完全に防止できるものではないため、Relying Party にも正しい OIDC validation を要求します。

---

### 4.5 Audience confusion

#### Threat

Client A 用に発行された ID Token を Client B が受け入れる。

#### Mitigation

`aud` は Provider の固定値にはしません。

認証 transaction に binding された `client_id` に基づいて client-specific audience を発行します。

```text
Client A -> aud = client-a
Client B -> aud = client-b
```

Relying Party は自分の `client_id` が audience として正しいことを必ず検証します。

---

### 4.6 Issuer confusion / hostname drift

#### Threat

request host や proxy configuration によって `iss` が変化し、同一 Provider が複数 issuer として振る舞う。

#### Mitigation

issuer は request から推測しません。

```env
OIDC_ISSUER_URL=https://discord.id.ojiverse.example
```

のような明示的 configuration を唯一の issuer source とします。

以下はすべて configured issuer と整合している必要があります。

- Discovery `issuer`
- authorization endpoint metadata
- token endpoint metadata
- JWKS URI metadata
- ID Token `iss`

issuer URL は production 利用開始後、長期的な issuer identifier として扱います。

---

### 4.7 Subject instability / account confusion

#### Threat

username、email、display name など変更可能な属性を user identity として利用し、account takeover や誤った account merge を起こす。

#### Mitigation

Discord-backed issuer の `sub` は Discord stable user ID (Snowflake) を使用します。

```text
canonical external identity = (iss, sub)
```

以下を account key にしません。

- email
- username
- global display name
- Guild nickname
- roles

---

### 4.8 Guild membership bypass

#### Threat

required Guild に所属していない Discord user が OIDC authentication を完了する。

#### Mitigation

Discord user validation と Guild membership validation の両方が成功するまで Provider authorization code を発行しません。

`guilds.members.read` scope を利用し、`GET /users/@me/guilds/{guild_id}/member` で required Guild への membership を直接照会します。member object が返れば member、404 であれば non-member と判定します。

API error、rate limit、判定不能な response では fail-open せず authentication を失敗させます。

### Membership revocation latency

Guild membership は login 時点で検証します。

したがってユーザーが Guild から退出/ban された後でも、すでに発行済みの ID Token や RP session が expiry まで有効な可能性があります。

これは明示的な設計上の trade-off です。

対策として:

- ID Token を短命にする(初期値 15 分)
- RP session policy を適切に設定する
- 高リスク用途では再認証間隔を短くする

ことを推奨します。

即時 revocation が必要になった場合は別途 session/introspection/revocation architecture を設計します。

---

### 4.9 Discord OAuth token leakage

#### Threat

Discord access token / refresh token がログ、Relying Party、storage へ不要に残る。

#### Mitigation

Discord token は Discord user と Guild membership を確認するための一時 credential として扱います。

- Relying Party へ返さない
- application log に出さない
- authentication だけが目的なら長期保存しない
- error response に含めない

将来 Discord API access delegation を提供したくなった場合は、この OIDC authentication flow とは別機能として設計します。

---

### 4.10 Signing key compromise

#### Threat

OIDC signing private key が漏洩し、攻撃者が正規 ID Token を偽造する。

#### Mitigation

- private key を Git に保存しない
- Cloudflare Worker Secret 等の secret storage を利用
- public key のみ JWKS で公開
- `kid` を付与
- key rotation 手順を用意
- repository / deployment token の権限を最小化

private signing key を通常の KV や public configuration に plaintext で保持する設計は避けます。

### Key rotation

rotation 時には:

1. new key pair を導入
2. new key で token signing を開始
3. old + new public key を JWKS で一定期間公開
4. old key で署名された全 token の expiry 後に old public key を削除
5. old private key を破棄

できる設計を目標とします。

---

### 4.11 Client secret leakage

confidential OIDC client を導入する場合、client secret は repository や `OIDC_CLIENTS_JSON` のような公開設定へ含めません。

secret は Cloudflare secret storage へ格納し、client authentication method は `client_secret_basic` とします。

初期の browser/public clients については client secret に依存せず PKCE を使用します。

---

### 4.12 SSRF / arbitrary upstream requests

Discord API / OAuth endpoint を request parameter で変更可能にしません。

Provider が outbound request を行う destination は実装/configurationによって固定します。

OIDC issuer URL や redirect URI を outbound fetch target としてそのまま利用しません。

---

### 4.13 Abuse / resource exhaustion

Public authorization endpoint は abuse の対象になり得ます。

必要に応じて Cloudflare の機能を利用し、以下を検討します。

- per-IP / per-client rate limiting
- WAF rules
- abnormal token endpoint traffic detection
- authorization transaction 数の制限
- expired state の定期 cleanup
- request body / query size limits

認証失敗時の処理が高コストな Discord API request を無制限に誘発しないようにします。

---

## 5. PKCE policy

初期方針として PKCE `S256` を必須にすることを推奨します。

```text
code_challenge_method = S256
```

`plain` は許可しません。

confidential client で client authentication を行う場合でも、Authorization Code Flow の defense-in-depth として PKCE を利用できる設計を優先します。

---

## 6. Client registry security

Static client registry は security boundary です。

client registration には少なくとも以下を明示します。

```text
client_id
client type
allowed redirect URIs
allowed scopes
client authentication method
```

configuration change は code/config review の対象にします。

Dynamic Client Registration は初期スコープ外です。

---

## 7. Cloudflare security boundary

`discord-oidc` と Relying Party が同じ Cloudflare Account に存在しても、同一 security principal として扱いません。

推奨:

- repository を分離
- CI/CD credential を分離
- API token scope を必要最小限にする
- secrets を分離
- Durable Object / storage を共有しない

OIDC Provider の compromise が自動的に Relying Party の deployment 権限取得へつながらないようにします。逆方向も同様です。

---

## 8. Logging / observability

authentication failure を追跡できるだけの observability は必要ですが、credential leakage を起こしてはいけません。

ログに残してよい候補:

- generated request/correlation ID
- endpoint
- OIDC client ID
- success / failure category
- latency
- Discord API status code
- authorization transaction ID の非機密 identifier

ログへ残してはいけないもの:

- Discord access / refresh token
- authorization code
- PKCE verifier
- client secret
- signing private key
- full ID Token
- session cookie

`sub` をログへ記録する必要がある場合も、運用要件を確認し、必要最小限にします。

---

## 9. Cookies

内部 flow で cookie を使用する場合は最低限:

```text
Secure
HttpOnly
SameSite=Lax (flowに応じて検証)
```

を設定します。

cookie に Discord access token、signing key、client secret を直接格納しません。

client-side state へ security-sensitive data を持たせる場合は、署名だけでなく confidentiality が必要かも含めて個別に評価します。

---

## 10. OIDC metadata / JWKS

Discovery metadata は実装と一致していなければなりません。

未実装の feature を `*_supported` に列挙しないようにします。

JWKS には private key material を絶対に含めません。

JWK の公開項目と `kid` / `alg` が実際の ID Token signing header と一致することを test します。

---

## 11. Dependency security

OIDC/JWT/crypto の独自実装範囲は最小限にします。

- JWT signature algorithm
- PKCE calculation
- JWK import/export
- token claim validation

などは、Cloudflare Workers runtime と十分に保守された library を利用します。

security-sensitive dependency は lockfile で固定し、Renovate / Dependabot 等による更新監視を検討します。

---

## 12. Testing requirements

少なくとも以下を automated test 対象にします。

### Authorization endpoint

- unknown client rejection
- exact redirect URI matching
- missing `openid` scope
- invalid response type
- invalid/missing PKCE

### Discord callback

- invalid upstream state
- Discord token exchange failure
- invalid Discord user response
- required Guild non-member
- Guild API failure / incomplete response

### Token endpoint

- unknown code
- expired code
- already consumed code
- wrong `grant_type`
- missing / invalid client authentication
- wrong client
- wrong redirect URI
- wrong PKCE verifier
- atomic double exchange

### ID Token

- exact configured `iss`
- Discord Snowflake mapped to `sub`
- client-specific `aud`
- correct expiry
- nonce preservation
- valid signature
- current `kid` available from JWKS

### Key rotation

- old token remains verifiable during overlap period
- new token uses new `kid`
- private key is never present in JWKS

---

## 13. Security reporting

実際の脆弱性、credential leakage、authentication bypass の可能性を発見した場合は、公開 Issue への詳細な exploit 情報の投稿を避けてください。

GitHub Private Vulnerability Reporting / Security Advisory が利用可能な場合は private channel を使用します。

security incident では、必要に応じて以下を直ちに rotation / revocation 対象とします。

- Discord client secret
- OIDC signing key
- confidential client secret
- Cloudflare deployment/API token

---

## 14. Prior art

本プロジェクトは [Erisa/discord-oidc-worker](https://github.com/Erisa/discord-oidc-worker) を参考にしています。

同実装の Discord OAuth2 + Cloudflare Workers + OIDC という構成を先行事例として参照していますが、本プロジェクトでは single-Guild / multi-client OpenID Provider として security boundary を整理し、Provider 自身の authorization code、client-specific `aud`、stable configurable issuer、required Guild membership verification を明示的に設計します。

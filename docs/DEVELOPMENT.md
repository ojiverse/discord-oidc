# Development

This repository implements the OpenID Provider described in `docs/DESIGN.md`
and `docs/SECURITY.md` in Rust on Cloudflare Workers (workers-rs).

## Layout

- `crates/oidc-core` — platform-agnostic provider logic: configuration and
  client-registry validation, `/authorize` request validation, authorization
  transaction and code lifecycle, PKCE, ID Token assembly, JWKS, discovery
  metadata, Discord callback orchestration, and `/token` handling. Signing
  is abstracted behind the `IdTokenSigner` trait; the crate carries no
  cryptographic signing implementation of its own. It compiles and tests on
  the host; all endpoints produce a runtime-neutral `CoreResponse`.
- `crates/discord-oidc-worker` — the Cloudflare Worker: HTTP routing,
  environment/secret loading, the singleton `AuthorizationState` Durable
  Object (SQLite-backed via `new_sqlite_classes`), the Discord API client,
  and the `IdTokenSigner` implementation backed by Workers Web Crypto
  (`crypto.subtle` RSASSA-PKCS1-v1_5) so private-key operations run in
  constant-time native code.
- `wrangler.toml` — Worker manifest: custom build, public vars, Durable
  Object binding, and the SQLite-class migration.
- `.github/workflows/ci.yml` — format, lint, host tests, `cargo audit`
  (RustSec advisories), wasm build, and a wrangler packaging dry-run.
  Actions are pinned to commit SHAs; `worker-build`, `wrangler`, and
  `cargo-audit` are version-pinned.
- `.github/workflows/cd.yml` — production deploy. Runs when a `ci` run on
  `main` completes successfully (`workflow_run`), or manually via
  `workflow_dispatch`. See "Deployment" below.

The boundary between the crates is the point of the design: everything an
attacker could probe lives in `oidc-core` and is covered by host-side tests;
the worker crate only adapts IO (fetch, DO storage, secrets, randomness).

## Toolchain

Rust stable with the `wasm32-unknown-unknown` target (see
`rust-toolchain.toml`), `worker-build` on PATH (`cargo install worker-build`
is also run by the wrangler build command), and Node.js for `wrangler` itself
(`npx wrangler@4`).

## Common tasks

- `cargo test --workspace` — host-side test suite covering the security
  properties in `docs/SECURITY.md` end to end.
- `cargo clippy --workspace --all-targets` and
  `cargo clippy -p discord-oidc-worker --target wasm32-unknown-unknown` —
  lint; CI denies warnings.
- `cargo fmt --all` — format.
- `worker-build --release crates/discord-oidc-worker` — wasm + wasm-bindgen
  packaging into `crates/discord-oidc-worker/build/`.
- `npx wrangler@4 deploy --dry-run` — validates the full wrangler build path.
- `npx wrangler@4 dev` — local dev server; needs `.dev.vars` (see
  `.dev.vars.example`) plus the public vars in `wrangler.toml`.

## Configuration model

Public vars in `wrangler.toml`: `OIDC_ISSUER_URL`, `DISCORD_CLIENT_ID`,
`DISCORD_REQUIRED_GUILD_ID`, `OIDC_CLIENTS_JSON`, `OIDC_SIGNING_KEY_ID`, and
optionally `OIDC_JWKS_ADDITIONAL_PUBLIC_KEYS` and `OIDC_ID_TOKEN_TTL_SECONDS`.

Secrets via `wrangler secret put` (or `.dev.vars` locally):
`DISCORD_CLIENT_SECRET`, `OIDC_SIGNING_PRIVATE_KEY`, and
`OIDC_CLIENT_SECRETS_JSON` when confidential clients are registered.

`OIDC_ISSUER_URL` must be an HTTPS origin with no path (endpoints are
routed at fixed root paths). `OIDC_SIGNING_PRIVATE_KEY` must be an
RSA ≥2048 PKCS#8 key (PEM `-----BEGIN PRIVATE KEY-----` or base64 DER);
PKCS#1 is not accepted. Generate one with
`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`.

The Discord application's redirect URI must be the issuer URL plus
`/oauth/discord/callback`.

## Storage

`AuthorizationState` is a single logical Durable Object (`id_from_name`)
holding `tx:{discord_oauth_state}` and `code:{code_hash}` records. Code
consume is check-and-delete inside one serialized object event; expired
records are removed by a storage alarm sweep every two minutes while entries
remain.

## Deployment

`.github/workflows/cd.yml` deploys to production. It triggers on a
successful `ci` run on `main` (`workflow_run`, deploying the exact commit
CI validated) and on `workflow_dispatch` for manual deploys. The job uses
the `production` GitHub environment and runs serially — an in-flight deploy
is never cancelled.

Secrets come from 1Password, not GitHub secrets. The job requests a GitHub
OIDC token (`id-token: write`), which `1password/load-secrets-action`
exchanges for short-lived access through 1Password's Credential Broker
(Workload Identity, public preview). Every variable in the linked 1Password
Environment is exported into the job; the Environment must therefore
contain only what deploy needs: `CLOUDFLARE_API_TOKEN`,
`DISCORD_CLIENT_SECRET`, `OIDC_SIGNING_PRIVATE_KEY`, and
`OIDC_CLIENT_SECRETS_JSON` when confidential clients are registered.

The job then runs `wrangler deploy` (which rebuilds the wasm via the
`[build]` command and applies Durable Object migrations), syncs the Worker
secrets with `wrangler secret bulk`, and finishes with a smoke check that
fetches the discovery document and JWKS from `OIDC_ISSUER_URL` — so a
deploy is only green once the live Worker answers correctly.
`secret bulk` is upsert-only: removing a Worker secret is a manual
`wrangler secret delete`.

One-time setup, none of which lives in the repository:

- Cloudflare: create the `workers.dev` subdomain (open Workers & Pages in
  the dashboard once) and an API token with Workers Scripts edit on the
  account; put the account ID in the `CLOUDFLARE_ACCOUNT_ID` repo variable.
- 1Password: an admin connects the GitHub organization under Developer →
  integrations → GitHub Actions, which yields `OP_INTEGRATION_KEY` (kept as
  a GitHub organization secret). The `discord-oidc-prod` Environment holds
  the variables above and its GitHub Actions destination is restricted to
  this repository's `cd.yml` on `main`. `OP_WORKLOAD_ID` and
  `OP_ENVIRONMENT_ID` are repo variables.
- GitHub: create the `production` environment, optionally with required
  reviewers.
- `wrangler.toml` `[vars]` must contain the real public values
  (`OIDC_ISSUER_URL`, `DISCORD_CLIENT_ID`, `DISCORD_REQUIRED_GUILD_ID`,
  `OIDC_CLIENTS_JSON`, `OIDC_SIGNING_KEY_ID`) before the first deploy —
  they are non-secret and committed, and the smoke check fails while they
  remain placeholders.

## Not implemented (out of scope for now)

`/userinfo`, Dynamic Client Registration, pairwise subjects, refresh tokens,
`email` scope, and Guild role claims — matching the documented non-goals in
`docs/DESIGN.md`.

Only the `openid` scope is supported. The opaque `access_token` returned by
`/token` is not bound to UserInfo or any other protected resource. OIDC
`prompt`/`max_age` values this provider cannot satisfy (`none`, `login`,
`select_account`, any `max_age`) fail closed with `login_required` /
`account_selection_required`; `prompt=consent` is forwarded to Discord's
consent re-approval prompt.

## Pre-production smoke test

Web Crypto signing and the live Discord OAuth exchange cannot be fully
verified on the host. Before production use, run this checklist against a
preview/staging Worker with a test Discord application:

- `/.well-known/openid-configuration` issuer/endpoints match the real URL
- `/jwks.json` publishes the JWK corresponding to the signing key
- `scope=openid` Authorization Code Flow completes end to end
- the issued ID Token verifies as RS256 against JWKS, with expected `iss`,
  `sub`, client-specific `aud`, `nonce`, `iat`, `exp`
- a required-Guild member succeeds; a non-member fails closed
- a wrong PKCE verifier returns `invalid_grant`; code replay fails
- `prompt=none`, `prompt=login`, and `max_age` return `login_required`
  without reaching Discord or issuing tokens
- `prompt=consent` adds `prompt=consent` to the Discord authorize URL

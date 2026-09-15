# Development

This repository implements the OpenID Provider described in `docs/DESIGN.md`
and `docs/SECURITY.md` in Rust on Cloudflare Workers (workers-rs).

## Layout

- `crates/oidc-core` — platform-agnostic provider logic: configuration and
  client-registry validation, `/authorize` request validation, authorization
  transaction and code lifecycle, PKCE, RS256 ID Token issuance, JWKS,
  discovery metadata, Discord callback orchestration, and `/token` handling.
  It compiles and tests on the host; all endpoints produce a runtime-neutral
  `CoreResponse`.
- `crates/discord-oidc-worker` — the Cloudflare Worker: HTTP routing,
  environment/secret loading, the singleton `AuthorizationState` Durable
  Object (SQLite-backed via `new_sqlite_classes`), and the Discord API client.
- `wrangler.toml` — Worker manifest: custom build, public vars, Durable
  Object binding, and the SQLite-class migration.
- `.github/workflows/ci.yml` — format, lint, host tests, wasm build, and a
  wrangler packaging dry-run.

The boundary between the crates is the point of the design: everything an
attacker could probe lives in `oidc-core` and is covered by host-side tests;
the worker crate only adapts IO (fetch, DO storage, secrets, randomness).

## Toolchain

Rust stable with the `wasm32-unknown-unknown` target (see
`rust-toolchain.toml`), `worker-build` on PATH (`cargo install worker-build`
is also run by the wrangler build command), and Node.js for `wrangler` itself
(`npx wrangler@4`).

## Common tasks

- `cargo test --workspace` — host-side test suite covering the SECURITY.md
  §12 matrix end to end.
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

The Discord application's redirect URI must be the issuer URL plus
`/oauth/discord/callback`.

## Storage

`AuthorizationState` is a single logical Durable Object (`id_from_name`)
holding `tx:{discord_oauth_state}` and `code:{code_hash}` records. Code
consume is check-and-delete inside one serialized object event; expired
records are removed by a storage alarm sweep every two minutes while entries
remain.

## Not implemented (out of scope for now)

`/userinfo`, Dynamic Client Registration, pairwise subjects, refresh tokens,
`email` scope, and Guild role claims — matching the non-goals in
`docs/DESIGN.md` §12. Deploy automation is intentionally absent; CI stops at
the packaging dry-run.

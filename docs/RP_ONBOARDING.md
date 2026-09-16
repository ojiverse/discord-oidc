# RP Onboarding Runbook

Operator procedure for registering a new OIDC Relying Party (RP) on a
discord-oidc deployment — for OJIverse, `https://discord.id.ojiver.se`.

- This document is the **end-to-end procedure**: what to collect, what to
  check, what to hand back, and how to manage the client afterwards.
- The **command reference** (exact requests and response shapes) lives in
  [DEVELOPMENT.md → Admin API](DEVELOPMENT.md#admin-api-rp-onboarding).
- The **developer-facing description** of the flow is in
  [README.md → Relying Party として接続する](../README.md).

## Roles

| Role      | Responsibility                                                        |
| --------- | --------------------------------------------------------------------- |
| Developer | Builds a standard OIDC RP; submits registration info to an operator.  |
| Operator  | Holds `OIDC_ADMIN_API_TOKEN`; registers and manages clients.          |

There is no self-service registration (RFC 7591 is intentionally not
implemented). Every client is registered by an operator via the admin API.

## Prerequisites

- `OIDC_ADMIN_API_TOKEN` is set in the `discord-oidc-prod` 1Password
  Environment and has been synced to the Worker secret by the deploy
  workflow. Without it every `/admin/*` request fails closed with 401.
- All admin requests authenticate with `Authorization: Bearer <token>`;
  responses are JSON with `Cache-Control: no-store` and no CORS headers.

## Step 1 — Collect the request

Ask the developer for:

| Field                   | Rule                                                                                              |
| ----------------------- | ------------------------------------------------------------------------------------------------- |
| `display_name`          | Human-readable service name; 1–128 UTF-8 bytes after trimming.                                    |
| `owner_discord_user_id` | The developer's Discord user ID (15–22 digit snowflake). Accountability contact only — never verified against the Discord API and not used in authorization decisions. |
| `redirect_uris`         | 1–16 unique exact-match URIs. Absolute URLs; HTTPS required (HTTP allowed only on `localhost`, `127.0.0.1`, `[::1]` for local development); no fragments; no `*` wildcards. |
| `client_type`           | `confidential` if a server backend can hold a secret; `public` for SPAs / native apps (PKCE-only). |

Guidance for `client_type`: prefer `public` when in doubt. Authorization
Code + PKCE (`S256`) is enforced either way; a confidential client adds a
secret only when a server side can actually protect it.

## Step 2 — Sanity-check the request

- **Redirect URIs are exact-match.** The provider never falls back to
  prefix matching, so a mistyped URI simply fails at `/authorize` — but a
  *wrong-but-valid* URI silently becomes a place authorization codes can
  be delivered. Confirm each origin belongs to the requesting service.
- **`client_type` is immutable**, as are `client_id`,
  `token_endpoint_auth_method`, and `allowed_scopes` (always `["openid"]`).
  A wrong choice cannot be patched — it requires registering a new client.
- `owner_discord_user_id` only needs to *look like* a snowflake; still,
  record the real requester so the client has an accountable owner.

## Step 3 — Register the client

`POST /admin/clients` — see
[DEVELOPMENT.md → Admin API](DEVELOPMENT.md#admin-api-rp-onboarding) for
the exact request body.

The `201` response carries the server-generated `client_id`
(`oji_` + 22 base64url characters). For `confidential` clients it also
carries `client_secret` — **shown exactly once** and never stored
recoverably (only its SHA-256 hash persists). Copy it out of the response
immediately.

## Step 4 — Verify registration

- `GET /admin/clients/{client_id}` shows `"status": "active"` and
  `"source": "dynamic"`.
- Optional smoke check: build an `/authorize` URL with the registered
  `client_id`, a registered `redirect_uri`, `scope=openid`, and a PKCE
  `code_challenge` — a healthy client redirects (302) to Discord.

## Step 5 — Hand over to the developer

Provide:

- `client_id`
- `client_secret` — **confidential clients only**, via a secure channel
  (e.g. 1Password share or encrypted DM). Never paste it into a ticket,
  issue, chat channel, or log.
- Issuer URL (`https://discord.id.ojiver.se`) — a standard OIDC library
  configures itself from `/.well-known/openid-configuration`.

## Lifecycle operations

| Task                  | Endpoint                                      | Notes                                                                                  |
| --------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------- |
| Update metadata       | `PUT /admin/clients/{id}`                     | Full replacement of `display_name` / `owner_discord_user_id` / `redirect_uris`.       |
| Rotate secret         | `POST /admin/clients/{id}/rotate-secret`      | New secret shown once; the previous secret stays valid for 600 s for rollout.         |
| Suspend               | `POST /admin/clients/{id}/disable`            | Immediate: `/authorize`, the Discord callback, and `/token` all reject the client.    |
| Resume                | `POST /admin/clients/{id}/enable`             | Re-enables immediately.                                                                |
| Retire                | `POST /admin/clients/{id}/disable`            | There is no delete endpoint; `disable` is retirement.                                 |
| Change `client_type`  | —                                             | Impossible; register a new client and disable the old one.                            |

Disable is idempotent and takes effect on the next request — no redeploy.
A client disabled mid-flow (between `/authorize` and the Discord callback)
is stopped at the callback: no token exchange, no code issued, no redirect
back to the RP.

## Static vs dynamic clients

- **Dynamic** (this runbook): everything registered at runtime. Preferred
  for all new RPs.
- **Static** (`OIDC_CLIENTS_JSON` in `wrangler.toml`): bootstrap/trusted
  clients such as `local-dev` and `cloudflare-access`. Readable through
  GET/list with `"source": "static"` but every mutation is rejected with
  `409 static_client_immutable` — changes require editing the config and
  redeploying. Static entries always win over a dynamic record with the
  same `client_id`.

## Errors

| HTTP | `error`                  | Meaning                                                              |
| ---- | ------------------------ | -------------------------------------------------------------------- |
| 400  | `invalid_request`        | Validation failed; `error_description` names the violated rule.      |
| 400  | `client_has_no_secret`   | Secret rotation attempted on a public client.                        |
| 401  | `unauthorized`           | Missing/wrong bearer token — also returned when the Worker secret is unset. |
| 404  | `client_not_found`       | No static or dynamic client with that `client_id`.                   |
| 404  | `not_found`              | Unknown `/admin/*` path.                                             |
| 405  | `method_not_allowed`     | Wrong HTTP method for the path.                                      |
| 409  | `static_client_immutable`| Mutation attempted on a static client.                               |
| 500  | `storage_error`          | Durable Object failure; safe to retry.                               |

## Security notes

- Never log or echo the admin token or a `client_secret`. The API never
  returns secret material on GET/list — only on create/rotate.
- To rotate the admin token: update the 1Password variable and re-sync
  Worker secrets (rerun the deploy workflow or `wrangler secret bulk`).
- To revoke it entirely: `wrangler secret delete OIDC_ADMIN_API_TOKEN` —
  the admin API then fails closed with 401 until a new secret is synced.

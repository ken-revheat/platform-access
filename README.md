# @revheat/platform-access

Shared platform access layer for RevHeat products — one implementation of SSO
identity verification and per-product entitlement, consumed as a pinned git
dependency across products (mirrors `@revheat/session-keeper`).

- `@revheat/platform-access/core` — isomorphic (edge/node/browser): `parseSessionInfo`,
  `verifyAccessToken` (jose HS256), `resolveOrg`, `resolveProducts` (tri-state),
  `getEntitlement` (`entitled | locked | needs_grant | none | indeterminate`), `safeNextUrl`,
  and the `createPlatformAccess({ productCode, selfHost, apiBaseUrl?, portalUrl? })` factory.
- `@revheat/platform-access/next` — Next.js request wrapper: `getTrustedContext`,
  `requireEntitledContext`, `createProxy`.

The platform monolith's `ProductAccessGuard` remains server-side truth; this package
is a *client* of `GET /api/me/products`. A transient platform error yields
`indeterminate`, never a false "not entitled".

## ⛔ Access is decided by `state === "launch"` and NOTHING else

`/api/me/products` returns one row per CATALOG entry, not per entitlement, so most
rows describe products the user CANNOT open. Never gate on `lockReason` (it is null
for three of the four wire states) or `billingStatus` (it is a live `active` on
`needs_grant`). Gating on `lockReason` was a live revenue hole, found 2026-07-20 and
fixed in v2.0.0 — every version before that is unsafe.

| verdict | meaning | what to render |
|---|---|---|
| `entitled` | `state: launch` — may enter | the product |
| `needs_grant` | org PAID, this user has no seat | "ask your admin for a seat" — never an upsell, never a billing error |
| `none` | org owns nothing | upsell |
| `locked` | billing lapsed, or an unrecognized state (fail-closed default) | reactivate |
| `indeterminate` | transient failure | retry — NEVER a denial or upsell |

Dunning (`past_due`) and `trialing` customers both emit `launch` and MUST keep access;
dunning is surfaced through the separate `billingStatus` field only.

**Consumers must branch on `entitled` POSITIVELY** — `if (ent === "entitled") { ... }
else { deny }` — never fall through to the product on "none of the above". A verdict
added to this union in future must cost a user an access screen, never open a door.

Recipe: committed `dist/`, `compile` (not `build`) script, `.js`-extension imports,
pinned per consumer by tag. Build: `npm run compile`. Test: `npm test`.

# @revheat/platform-access

Shared platform access layer for RevHeat products — one implementation of SSO
identity verification and per-product entitlement, consumed as a pinned git
dependency across products (mirrors `@revheat/session-keeper`).

- `@revheat/platform-access/core` — isomorphic (edge/node/browser): `parseSessionInfo`,
  `verifyAccessToken` (jose HS256), `resolveOrg`, `resolveProducts` (tri-state),
  `getEntitlement` (`entitled | locked | none | indeterminate`), `safeNextUrl`,
  and the `createPlatformAccess({ productCode, selfHost, apiBaseUrl?, portalUrl? })` factory.
- `@revheat/platform-access/next` — Next.js request wrapper: `getTrustedContext`,
  `requireEntitledContext`, `createProxy`.

The platform monolith's `ProductAccessGuard` remains server-side truth; this package
is a *client* of `GET /api/me/products`. A transient platform error yields
`indeterminate`, never a false "not entitled".

Recipe: committed `dist/`, `compile` (not `build`) script, `.js`-extension imports,
pinned per consumer by tag. Build: `npm run compile`. Test: `npm test`.

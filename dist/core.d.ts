/**
 * @revheat/platform-access/core — isomorphic (edge/node/browser) trusted-identity
 * primitives shared by every RevHeat product.
 *
 * This module is the platform-agnostic extraction of QuotaFit's
 * src/lib/identity-core.ts + src/lib/auth.ts. It is PURE and dependency-injectable
 * (no next/headers, no "server-only", no module-scope env/Buffer reads) so it stays
 * isomorphic — jose runs the same way on the edge runtime, Node, and in the browser.
 *
 * The only product-specific values — PRODUCT_CODE and SELF_HOST in the original
 * QuotaFit module — are now constructor args of `createPlatformAccess(...)`. Every
 * consumer of this factory's `core` gets the exact same verify/resolve/entitlement
 * behavior QuotaFit already runs in production; only the product identity differs.
 */
/**
 * HttpOnly, signed-JWT access token cookie. This is the cookie the SERVER trusts:
 * its signature is verified (HS256, shared JWT_ACCESS_SECRET) before any
 * org-scoped data access. JS can never read it, so it is NOT used by the edge UX
 * gate (that reads SESSION_COOKIE instead). Same cookie name for every RevHeat
 * product (Domain=.revheat.com SSO) — NOT product-specific, so unlike
 * productCode/selfHost this stays a plain constant rather than a factory arg.
 */
export declare const ACCESS_COOKIE = "revheat_access_token";
/**
 * JS-readable session hint cookie (single-encoded JSON; do NOT double-decode).
 * UX gating only, NEVER a security boundary — see parseSessionInfo. Same cookie
 * name for every RevHeat product.
 */
export declare const SESSION_COOKIE = "revheat_session_info";
/** A cryptographically trusted user (from a verified access-token signature). */
export interface TrustedUser {
    userId: string;
}
/** A trusted org, as the platform reports it for the verified user. */
export interface TrustedOrg {
    orgId: string;
    /** Human-readable org name from the platform — used to seed the local mirror. */
    orgName: string;
}
/** A fully resolved tenant context: trusted user + trusted org. */
export interface TrustedContext {
    userId: string;
    orgId: string;
    orgName: string;
}
/** Injectable seams for platform calls (fetch, clock, base URL) — for tests. */
export interface ResolveDeps {
    fetchImpl?: typeof fetch;
    now?: () => number;
    apiBaseUrl?: string;
}
/** How long a platform call should wait before failing closed. */
export declare const ORG_RESOLVE_TIMEOUT_MS = 5000;
/** Org cache TTL — see resolveOrg doc for staleness semantics. */
export declare const ORG_CACHE_TTL_MS = 30000;
/** Products cache TTL — mirrors ORG_CACHE_TTL_MS. Only definitive (ok) results cached. */
export declare const PRODUCTS_CACHE_TTL_MS = 30000;
/** A product entitlement as the platform reports it for the verified user. */
export interface Product {
    code: string;
    state: string;
    lockReason: string | null;
    billingStatus: string;
    appUrl: string | null;
}
/**
 * Tri-state products result. `indeterminate` is a distinct, explicit failure so a
 * transient platform error never masquerades as "no products" (which would upsell a
 * paying customer). Do NOT collapse this to a nullable list.
 */
export type ProductsResult = {
    status: "ok";
    products: Product[];
} | {
    status: "indeterminate";
};
export type Entitlement = "entitled" | "locked" | "none" | "indeterminate";
export interface SessionInfo {
    userId: string;
    orgId: string;
    email: string;
    productCodes: string[];
    /** Epoch MILLISECONDS (13-digit) — compare to Date.now() directly, do NOT ×1000. */
    expiresAt: number;
}
/** Options that parameterize a product's platform-access instance. */
export interface PlatformAccessOptions {
    /** This product's code in `organization_products` (e.g. "quotafit"). */
    productCode: string;
    /** This product's own host — the fallback when a request's Host can't be trusted. */
    selfHost: string;
    /** The platform API base. Defaults to https://api.revheat.com. */
    apiBaseUrl?: string;
    /** The portal that issues sessions. Defaults to https://app.revheat.com. */
    portalUrl?: string;
}
export interface PlatformAccessCore {
    readonly productCode: string;
    readonly selfHost: string;
    readonly apiBaseUrl: string;
    readonly portalUrl: string;
    /**
     * Verify a `revheat_access_token` signature and expiry. Returns the trusted user,
     * or null for any invalid/expired/missing token. `algorithms` is pinned to HS256
     * to defeat algorithm-confusion (`alg: none` or an RS256 swap — also structurally
     * impossible here since the key is a symmetric Uint8Array). `requiredClaims:["exp"]`
     * insures against a future platform bug ever minting a non-expiring token.
     *
     * `key` is required (no module-scope secret caching here — this module must stay
     * isomorphic with no node-only side effects at import time). Callers on Node
     * derive the key once from JWT_ACCESS_SECRET and pass it in.
     */
    verifyAccessToken(token: string | undefined | null, key: Uint8Array): Promise<TrustedUser | null>;
    /**
     * Resolve the trusted org (id + name) for a verified user by calling the platform's
     * `GET /api/org/me` with the user's access token forwarded as the Cookie. The
     * platform re-verifies the token and derives the org from active membership, so a
     * 200 `{ id, name }` is authoritative. Returns null on any non-200, network/timeout
     * error, malformed body, or non-UUID id (all fail closed). `name` is cosmetic
     * (used to seed the local mirror); a missing/blank name falls back to a default,
     * but a bad `id` always fails closed.
     *
     * INVARIANT: `token` must already have passed verifyAccessToken. This function
     * forwards it verbatim into a Cookie header (injection-safe only because a
     * signature-verified JWT is restricted to base64url + ".") and never trusts the
     * response for anything but the org the platform itself chose. Any new caller MUST
     * verify the token first.
     */
    resolveOrg(token: string, userId: string, deps?: ResolveDeps): Promise<TrustedOrg | null>;
    /** Back-compat thin wrapper: just the trusted orgId (or null). */
    resolveOrgId(token: string, userId: string, deps?: ResolveDeps): Promise<string | null>;
    /**
     * Resolve the verified product entitlements for a user by calling the platform's
     * `GET /api/me/products` with the access token forwarded as the Cookie. MIRRORS
     * resolveOrg (no-store, 5s timeout, per-user cache). Returns a tri-state result:
     * only a clean 200 with a products array is `ok` (and cached); every failure mode
     * (network/timeout/non-200/parse) is `indeterminate` and is NEVER cached.
     *
     * INVARIANT: `token` must already have passed verifyAccessToken (same contract as
     * resolveOrg — the JWT charset makes Cookie-header injection impossible).
     */
    resolveProducts(token: string, userId: string, deps?: ResolveDeps): Promise<ProductsResult>;
    /**
     * Map the verified products to THIS product's entitlement state. `indeterminate`
     * passes through so the caller can show "retry" (never upsell). A matching entry
     * with a null lockReason is entitled; a non-null lockReason is locked
     * (past-due/paused); absent is none. The product is found by the factory's
     * configured `productCode` — never a module constant.
     */
    getEntitlement(token: string, userId: string, deps?: ResolveDeps): Promise<Entitlement>;
    /**
     * Establish a full trusted context from a raw access-token string: verify the
     * signature -> trusted userId, then resolve the trusted orgId. Returns null if
     * either step fails (no/invalid token, or no active org membership).
     */
    getTrustedContextFromToken(token: string | undefined | null, key: Uint8Array, deps?: ResolveDeps): Promise<TrustedContext | null>;
    /**
     * Parse + validate a `revheat_session_info` cookie value. Returns the session
     * only when the shape is valid AND it has not expired. The wire format is
     * single-encoded JSON; tolerate a URL-encoded variant but never double-decode.
     */
    parseSessionInfo(raw: string | undefined | null): SessionInfo | null;
    /**
     * Build the public https return URL from a request's (untrusted) Host header.
     * Fail closed: if the Host isn't a `.revheat.com` subdomain, use this product's
     * configured selfHost — so a spoofed Host can't turn the portal `next` into an
     * off-domain open redirect, independent of the portal's own whitelist (defense
     * in depth).
     */
    safeNextUrl(host: string | null, pathAndQuery: string): string;
    /** Portal login URL with a return path. `next` must be a full https .revheat.com URL. */
    portalLoginUrl(next: string): string;
    /** Test helper: drop all cached orgs. */
    __clearOrgCache(): void;
    /** Test helper: drop all cached products. */
    __clearProductsCache(): void;
}
/**
 * Build an isomorphic platform-access core instance parameterized for one product.
 * Every RevHeat product calls this once with its own `productCode` + `selfHost` and
 * gets QuotaFit's exact verify/resolve/entitlement behavior for free.
 */
export declare function createPlatformAccessCore(options: PlatformAccessOptions): PlatformAccessCore;
//# sourceMappingURL=core.d.ts.map
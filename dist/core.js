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
import { jwtVerify } from "jose";
/**
 * HttpOnly, signed-JWT access token cookie. This is the cookie the SERVER trusts:
 * its signature is verified (HS256, shared JWT_ACCESS_SECRET) before any
 * org-scoped data access. JS can never read it, so it is NOT used by the edge UX
 * gate (that reads SESSION_COOKIE instead). Same cookie name for every RevHeat
 * product (Domain=.revheat.com SSO) — NOT product-specific, so unlike
 * productCode/selfHost this stays a plain constant rather than a factory arg.
 */
export const ACCESS_COOKIE = "revheat_access_token";
/**
 * JS-readable session hint cookie (single-encoded JSON; do NOT double-decode).
 * UX gating only, NEVER a security boundary — see parseSessionInfo. Same cookie
 * name for every RevHeat product.
 */
export const SESSION_COOKIE = "revheat_session_info";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** How long a platform call should wait before failing closed. */
export const ORG_RESOLVE_TIMEOUT_MS = 5000;
/** Org cache TTL — see resolveOrg doc for staleness semantics. */
export const ORG_CACHE_TTL_MS = 30000;
/** Products cache TTL — mirrors ORG_CACHE_TTL_MS. Only definitive (ok) results cached. */
export const PRODUCTS_CACHE_TTL_MS = 30000;
/** Fallback name when the platform omits one (orgId is the load-bearing field). */
const DEFAULT_ORG_NAME = "Organization";
function isSessionInfo(v) {
    if (!v || typeof v !== "object")
        return false;
    const o = v;
    return (typeof o.userId === "string" &&
        typeof o.orgId === "string" &&
        typeof o.email === "string" &&
        typeof o.expiresAt === "number" &&
        Array.isArray(o.productCodes));
}
function parseProduct(raw) {
    if (typeof raw !== "object" || raw === null)
        return null;
    const r = raw;
    if (typeof r.code !== "string")
        return null;
    return {
        code: r.code,
        state: typeof r.state === "string" ? r.state : "",
        lockReason: typeof r.lockReason === "string" ? r.lockReason : null,
        billingStatus: typeof r.billingStatus === "string" ? r.billingStatus : "",
        appUrl: typeof r.appUrl === "string" ? r.appUrl : null,
    };
}
/**
 * Build an isomorphic platform-access core instance parameterized for one product.
 * Every RevHeat product calls this once with its own `productCode` + `selfHost` and
 * gets QuotaFit's exact verify/resolve/entitlement behavior for free.
 */
export function createPlatformAccessCore(options) {
    const { productCode, selfHost } = options;
    const apiBaseUrl = options.apiBaseUrl ?? "https://api.revheat.com";
    const portalUrl = options.portalUrl ?? "https://app.revheat.com";
    // Per-instance caches — one product's cache is never shared with another's.
    const orgCache = new Map();
    const productsCache = new Map();
    async function verifyAccessToken(token, key) {
        if (!token)
            return null;
        try {
            const { payload } = await jwtVerify(token, key, {
                algorithms: ["HS256"],
                requiredClaims: ["exp"],
            });
            const userId = payload.userId;
            // The platform mints user ids with crypto.randomUUID(); require that shape so
            // a non-UUID id can never reach a @db.Uuid column (an opaque cast failure that
            // would take down every tenant write). Fail closed, consistent with orgId.
            if (typeof userId !== "string" || !UUID_RE.test(userId))
                return null;
            return { userId };
        }
        catch {
            // Bad signature, expired, malformed, wrong alg — all fail closed.
            return null;
        }
    }
    async function resolveOrg(token, userId, deps = {}) {
        const now = deps.now ?? Date.now;
        const cached = orgCache.get(userId);
        if (cached) {
            if (cached.expiresAt > now())
                return cached.org;
            orgCache.delete(userId); // evict on expiry so the Map can't grow unbounded
        }
        const doFetch = deps.fetchImpl ?? fetch;
        const base = deps.apiBaseUrl ?? apiBaseUrl;
        let res;
        try {
            res = await doFetch(`${base}/api/org/me`, {
                method: "GET",
                headers: { cookie: `revheat_access_token=${token}` },
                signal: AbortSignal.timeout(ORG_RESOLVE_TIMEOUT_MS),
                // SECURITY-CRITICAL: never cache this response. The URL is identical for
                // every user (only the forwarded Cookie differs, and Next does not key its
                // data cache on request headers) — caching would serve one user's orgId to
                // all of them. Do not "optimize" this away.
                cache: "no-store",
            });
        }
        catch {
            return null; // network error / timeout — fail closed
        }
        if (!res.ok)
            return null;
        let body;
        try {
            body = await res.json();
        }
        catch {
            return null;
        }
        const raw = body;
        const orgId = raw?.id;
        if (typeof orgId !== "string" || !UUID_RE.test(orgId))
            return null;
        const orgName = typeof raw?.name === "string" && raw.name.trim().length > 0
            ? raw.name
            : DEFAULT_ORG_NAME;
        const org = { orgId, orgName };
        orgCache.set(userId, { org, expiresAt: now() + ORG_CACHE_TTL_MS });
        return org;
    }
    async function resolveOrgId(token, userId, deps = {}) {
        return (await resolveOrg(token, userId, deps))?.orgId ?? null;
    }
    async function resolveProducts(token, userId, deps = {}) {
        const now = deps.now ?? Date.now;
        const cached = productsCache.get(userId);
        if (cached) {
            if (cached.expiresAt > now())
                return cached.result;
            productsCache.delete(userId);
        }
        const doFetch = deps.fetchImpl ?? fetch;
        const base = deps.apiBaseUrl ?? apiBaseUrl;
        let res;
        try {
            res = await doFetch(`${base}/api/me/products`, {
                method: "GET",
                headers: { cookie: `revheat_access_token=${token}` },
                signal: AbortSignal.timeout(ORG_RESOLVE_TIMEOUT_MS),
                // SECURITY-CRITICAL: never cache — URL is identical per user, only the Cookie
                // differs, and Next does not key its data cache on headers.
                cache: "no-store",
            });
        }
        catch {
            return { status: "indeterminate" }; // network/timeout — NOT cached
        }
        if (!res.ok)
            return { status: "indeterminate" }; // non-200 — NOT cached
        let body;
        try {
            body = await res.json();
        }
        catch {
            return { status: "indeterminate" }; // parse failure — NOT cached
        }
        const raw = body;
        if (!raw || !Array.isArray(raw.products))
            return { status: "indeterminate" };
        const products = raw.products
            .map(parseProduct)
            .filter((p) => p !== null);
        const result = { status: "ok", products };
        productsCache.set(userId, { result, expiresAt: now() + PRODUCTS_CACHE_TTL_MS });
        return result;
    }
    async function getEntitlement(token, userId, deps = {}) {
        const result = await resolveProducts(token, userId, deps);
        if (result.status === "indeterminate")
            return "indeterminate";
        const p = result.products.find((prod) => prod.code === productCode);
        if (!p)
            return "none";
        return p.lockReason !== null ? "locked" : "entitled";
    }
    async function getTrustedContextFromToken(token, key, deps = {}) {
        const user = await verifyAccessToken(token, key);
        if (!user)
            return null;
        // token is non-empty here (verifyAccessToken returns null for empty input).
        const org = await resolveOrg(token, user.userId, deps);
        if (!org)
            return null;
        return { userId: user.userId, orgId: org.orgId, orgName: org.orgName };
    }
    function parseSessionInfo(raw) {
        if (!raw)
            return null;
        let candidate;
        try {
            candidate = JSON.parse(raw);
        }
        catch {
            try {
                candidate = JSON.parse(decodeURIComponent(raw));
            }
            catch {
                return null;
            }
        }
        if (!isSessionInfo(candidate))
            return null;
        if (candidate.expiresAt <= Date.now())
            return null; // expiresAt is ms
        return candidate;
    }
    function safeNextUrl(host, pathAndQuery) {
        const h = host && host.endsWith(".revheat.com") ? host : selfHost;
        return `https://${h}${pathAndQuery}`;
    }
    function portalLoginUrl(next) {
        return `${portalUrl}/login?next=${encodeURIComponent(next)}`;
    }
    function __clearOrgCache() {
        orgCache.clear();
    }
    function __clearProductsCache() {
        productsCache.clear();
    }
    return {
        productCode,
        selfHost,
        apiBaseUrl,
        portalUrl,
        verifyAccessToken,
        resolveOrg,
        resolveOrgId,
        resolveProducts,
        getEntitlement,
        getTrustedContextFromToken,
        parseSessionInfo,
        safeNextUrl,
        portalLoginUrl,
        __clearOrgCache,
        __clearProductsCache,
    };
}
//# sourceMappingURL=core.js.map
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

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
export const ORG_RESOLVE_TIMEOUT_MS = 5000;

/** Org cache TTL — see resolveOrg doc for staleness semantics. */
export const ORG_CACHE_TTL_MS = 30_000;

/** Products cache TTL — mirrors ORG_CACHE_TTL_MS. Only definitive (ok) results cached. */
export const PRODUCTS_CACHE_TTL_MS = 30_000;

/** Fallback name when the platform omits one (orgId is the load-bearing field). */
const DEFAULT_ORG_NAME = "Organization";

/** A product entitlement as the platform reports it for the verified user. */
export interface Product {
  code: string;
  state: string;
  lockReason: string | null;
  billingStatus: string;
  appUrl: string | null;
}

/**
 * The verified identity behind an access token, as the platform reports it via
 * `GET /api/auth/me`. `email` is the login email on the platform User row;
 * `emailVerified` reflects the DB-backed `email_verified` flag verbatim. Consumers
 * establishing domain authorization from a company email MUST gate on
 * `emailVerified === true` — the platform never coerces it.
 */
export interface ViewerIdentity {
  email: string;
  emailVerified: boolean;
}

/**
 * Tri-state products result. `indeterminate` is a distinct, explicit failure so a
 * transient platform error never masquerades as "no products" (which would upsell a
 * paying customer). Do NOT collapse this to a nullable list.
 */
export type ProductsResult =
  | { status: "ok"; products: Product[] }
  | { status: "indeterminate" };

/**
 * This product's access verdict for one user.
 *
 * `needs_grant` is deliberately its OWN verdict rather than being folded into
 * "none" or "locked": the org HAS paid, this user just has no seat. Telling them
 * to buy it (none) or that billing lapsed (locked) are both lies that send them
 * to the wrong place. Consumers that do not yet render it still fail closed —
 * see getEntitlement's contract.
 */
export type Entitlement =
  | "entitled"
  | "locked"
  | "needs_grant"
  | "none"
  | "indeterminate";

export interface SessionInfo {
  userId: string;
  orgId: string;
  email: string;
  productCodes: string[];
  /** Epoch MILLISECONDS (13-digit) — compare to Date.now() directly, do NOT ×1000. */
  expiresAt: number;
}

function isSessionInfo(v: unknown): v is SessionInfo {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.userId === "string" &&
    typeof o.orgId === "string" &&
    typeof o.email === "string" &&
    typeof o.expiresAt === "number" &&
    Array.isArray(o.productCodes)
  );
}

function parseProduct(raw: unknown): Product | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.code !== "string") return null;
  return {
    code: r.code,
    state: typeof r.state === "string" ? r.state : "",
    lockReason: typeof r.lockReason === "string" ? r.lockReason : null,
    billingStatus: typeof r.billingStatus === "string" ? r.billingStatus : "",
    appUrl: typeof r.appUrl === "string" ? r.appUrl : null,
  };
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
  verifyAccessToken(
    token: string | undefined | null,
    key: Uint8Array,
  ): Promise<TrustedUser | null>;

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
  resolveOrg(
    token: string,
    userId: string,
    deps?: ResolveDeps,
  ): Promise<TrustedOrg | null>;

  /** Back-compat thin wrapper: just the trusted orgId (or null). */
  resolveOrgId(
    token: string,
    userId: string,
    deps?: ResolveDeps,
  ): Promise<string | null>;

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
  resolveProducts(
    token: string,
    userId: string,
    deps?: ResolveDeps,
  ): Promise<ProductsResult>;

  /**
   * Resolve the verified identity (email + emailVerified) for a user by calling the
   * platform's `GET /api/auth/me` with the access token forwarded as the Cookie.
   * MIRRORS resolveOrg (no-store, 5s timeout, fail closed). Returns null on any
   * non-200, network/timeout, malformed body, blank email, or non-boolean
   * emailVerified. Deliberately NOT cached and NOT tri-state: the sole caller uses it
   * to establish a durable domain-ownership record from a company email, and a null
   * simply means "can't email-match right now" — the caller falls back to a
   * DNS/meta-tag challenge, never a security downgrade.
   *
   * INVARIANT: `token` must already have passed verifyAccessToken (same
   * Cookie-injection-safety contract as resolveOrg/resolveProducts).
   */
  resolveViewerIdentity(
    token: string,
    userId: string,
    deps?: ResolveDeps,
  ): Promise<ViewerIdentity | null>;

  /**
   * Map the verified products to THIS product's entitlement state. `indeterminate`
   * passes through so the caller can show "retry" (never upsell). The product is
   * found by the factory's configured `productCode` — never a module constant.
   *
   * ⛔ The verdict is derived from `state` and NOTHING ELSE — never `lockReason`,
   * never `billingStatus`. Only `state === "launch"` grants access; every other
   * value, including one this library has never seen, denies. Callers MUST treat
   * any verdict other than `"entitled"` as no-access; branch on `"entitled"`
   * positively rather than falling through to the product on "none of the above",
   * so a future verdict added here cannot silently open a door.
   */
  getEntitlement(
    token: string,
    userId: string,
    deps?: ResolveDeps,
  ): Promise<Entitlement>;

  /**
   * Establish a full trusted context from a raw access-token string: verify the
   * signature -> trusted userId, then resolve the trusted orgId. Returns null if
   * either step fails (no/invalid token, or no active org membership).
   */
  getTrustedContextFromToken(
    token: string | undefined | null,
    key: Uint8Array,
    deps?: ResolveDeps,
  ): Promise<TrustedContext | null>;

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
export function createPlatformAccessCore(
  options: PlatformAccessOptions,
): PlatformAccessCore {
  const { productCode, selfHost } = options;
  const apiBaseUrl = options.apiBaseUrl ?? "https://api.revheat.com";
  const portalUrl = options.portalUrl ?? "https://app.revheat.com";

  // Per-instance caches — one product's cache is never shared with another's.
  const orgCache = new Map<string, { org: TrustedOrg; expiresAt: number }>();
  const productsCache = new Map<
    string,
    { result: { status: "ok"; products: Product[] }; expiresAt: number }
  >();

  async function verifyAccessToken(
    token: string | undefined | null,
    key: Uint8Array,
  ): Promise<TrustedUser | null> {
    if (!token) return null;
    try {
      const { payload } = await jwtVerify(token, key, {
        algorithms: ["HS256"],
        requiredClaims: ["exp"],
      });
      const userId = payload.userId;
      // The platform mints user ids with crypto.randomUUID(); require that shape so
      // a non-UUID id can never reach a @db.Uuid column (an opaque cast failure that
      // would take down every tenant write). Fail closed, consistent with orgId.
      if (typeof userId !== "string" || !UUID_RE.test(userId)) return null;
      return { userId };
    } catch {
      // Bad signature, expired, malformed, wrong alg — all fail closed.
      return null;
    }
  }

  async function resolveOrg(
    token: string,
    userId: string,
    deps: ResolveDeps = {},
  ): Promise<TrustedOrg | null> {
    const now = deps.now ?? Date.now;
    const cached = orgCache.get(userId);
    if (cached) {
      if (cached.expiresAt > now()) return cached.org;
      orgCache.delete(userId); // evict on expiry so the Map can't grow unbounded
    }

    const doFetch = deps.fetchImpl ?? fetch;
    const base = deps.apiBaseUrl ?? apiBaseUrl;

    let res: Response;
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
    } catch {
      return null; // network error / timeout — fail closed
    }

    if (!res.ok) return null;

    let body: unknown;
    try {
      body = await res.json();
    } catch {
      return null;
    }

    const raw = body as { id?: unknown; name?: unknown } | null;
    const orgId = raw?.id;
    if (typeof orgId !== "string" || !UUID_RE.test(orgId)) return null;
    const orgName =
      typeof raw?.name === "string" && raw.name.trim().length > 0
        ? raw.name
        : DEFAULT_ORG_NAME;

    const org: TrustedOrg = { orgId, orgName };
    orgCache.set(userId, { org, expiresAt: now() + ORG_CACHE_TTL_MS });
    return org;
  }

  async function resolveOrgId(
    token: string,
    userId: string,
    deps: ResolveDeps = {},
  ): Promise<string | null> {
    return (await resolveOrg(token, userId, deps))?.orgId ?? null;
  }

  async function resolveProducts(
    token: string,
    userId: string,
    deps: ResolveDeps = {},
  ): Promise<ProductsResult> {
    const now = deps.now ?? Date.now;
    const cached = productsCache.get(userId);
    if (cached) {
      if (cached.expiresAt > now()) return cached.result;
      productsCache.delete(userId);
    }

    const doFetch = deps.fetchImpl ?? fetch;
    const base = deps.apiBaseUrl ?? apiBaseUrl;

    let res: Response;
    try {
      res = await doFetch(`${base}/api/me/products`, {
        method: "GET",
        headers: { cookie: `revheat_access_token=${token}` },
        signal: AbortSignal.timeout(ORG_RESOLVE_TIMEOUT_MS),
        // SECURITY-CRITICAL: never cache — URL is identical per user, only the Cookie
        // differs, and Next does not key its data cache on headers.
        cache: "no-store",
      });
    } catch {
      return { status: "indeterminate" }; // network/timeout — NOT cached
    }

    if (!res.ok) return { status: "indeterminate" }; // non-200 — NOT cached

    let body: unknown;
    try {
      body = await res.json();
    } catch {
      return { status: "indeterminate" }; // parse failure — NOT cached
    }

    const raw = body as { products?: unknown } | null;
    if (!raw || !Array.isArray(raw.products)) return { status: "indeterminate" };

    const products = raw.products
      .map(parseProduct)
      .filter((p): p is Product => p !== null);

    const result = { status: "ok" as const, products };
    productsCache.set(userId, { result, expiresAt: now() + PRODUCTS_CACHE_TTL_MS });
    return result;
  }

  async function resolveViewerIdentity(
    token: string,
    _userId: string,
    deps: ResolveDeps = {},
  ): Promise<ViewerIdentity | null> {
    const doFetch = deps.fetchImpl ?? fetch;
    const base = deps.apiBaseUrl ?? apiBaseUrl;

    let res: Response;
    try {
      res = await doFetch(`${base}/api/auth/me`, {
        method: "GET",
        headers: { cookie: `revheat_access_token=${token}` },
        signal: AbortSignal.timeout(ORG_RESOLVE_TIMEOUT_MS),
        // SECURITY-CRITICAL: never cache — URL is identical per user, only the Cookie
        // differs, and Next does not key its data cache on headers.
        cache: "no-store",
      });
    } catch {
      return null; // network error / timeout — fail closed
    }

    if (!res.ok) return null;

    let body: unknown;
    try {
      body = await res.json();
    } catch {
      return null;
    }

    const raw = body as { email?: unknown; emailVerified?: unknown } | null;
    const email = raw?.email;
    const emailVerified = raw?.emailVerified;
    // Both fields must be present and well-typed. A blank email or a
    // non-boolean emailVerified can never establish trust — fail closed.
    const trimmed = typeof email === "string" ? email.trim() : "";
    if (trimmed.length === 0) return null;
    if (typeof emailVerified !== "boolean") return null;
    return { email: trimmed, emailVerified };
  }

  async function getEntitlement(
    token: string,
    userId: string,
    deps: ResolveDeps = {},
  ): Promise<Entitlement> {
    const result = await resolveProducts(token, userId, deps);
    if (result.status === "indeterminate") return "indeterminate";
    const p = result.products.find((prod) => prod.code === productCode);
    if (!p) return "none";
    // ⛔ Access is decided by `state` and ONLY `state`.
    //
    // This function used to read `lockReason !== null ? "locked" : "entitled"`,
    // which was a LIVE revenue hole (found 2026-07-20 in QuotaFit, from which this
    // library was ported while broken). `/api/me/products` returns one row per
    // CATALOG entry, not per entitlement, and products.service.ts sets
    // `lockReason: state === "locked_billing" ? ownStatus : null` — so a null
    // lockReason is true for THREE of the four wire states, only one of which
    // means the user may enter. `billingStatus` is no safer: it is a live
    // `active`/`trialing` on `needs_grant`.
    //
    // The default arm DENIES on purpose: a renamed or newly-added platform state
    // must cost a user an access screen, never cost us revenue.
    switch (p.state) {
      case "launch":
        return "entitled"; // paid + this user has a seat
      case "available":
        return "none"; // org owns nothing — upsell tile
      case "needs_grant":
        return "needs_grant"; // org paid, this user has no seat
      case "locked_billing":
      default:
        return "locked";
    }
  }

  async function getTrustedContextFromToken(
    token: string | undefined | null,
    key: Uint8Array,
    deps: ResolveDeps = {},
  ): Promise<TrustedContext | null> {
    const user = await verifyAccessToken(token, key);
    if (!user) return null;
    // token is non-empty here (verifyAccessToken returns null for empty input).
    const org = await resolveOrg(token as string, user.userId, deps);
    if (!org) return null;
    return { userId: user.userId, orgId: org.orgId, orgName: org.orgName };
  }

  function parseSessionInfo(
    raw: string | undefined | null,
  ): SessionInfo | null {
    if (!raw) return null;
    let candidate: unknown;
    try {
      candidate = JSON.parse(raw);
    } catch {
      try {
        candidate = JSON.parse(decodeURIComponent(raw));
      } catch {
        return null;
      }
    }
    if (!isSessionInfo(candidate)) return null;
    if (candidate.expiresAt <= Date.now()) return null; // expiresAt is ms
    return candidate;
  }

  function safeNextUrl(host: string | null, pathAndQuery: string): string {
    const h = host && host.endsWith(".revheat.com") ? host : selfHost;
    return `https://${h}${pathAndQuery}`;
  }

  function portalLoginUrl(next: string): string {
    return `${portalUrl}/login?next=${encodeURIComponent(next)}`;
  }

  function __clearOrgCache(): void {
    orgCache.clear();
  }

  function __clearProductsCache(): void {
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
    resolveViewerIdentity,
    getEntitlement,
    getTrustedContextFromToken,
    parseSessionInfo,
    safeNextUrl,
    portalLoginUrl,
    __clearOrgCache,
    __clearProductsCache,
  };
}

import "server-only";

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { NextResponse, type NextRequest } from "next/server";

import {
  ACCESS_COOKIE,
  SESSION_COOKIE,
  type Entitlement,
  type PlatformAccessCore,
  type ResolveDeps,
  type TrustedContext,
  type ViewerIdentity,
} from "./core.js";

export type { TrustedContext, ViewerIdentity } from "./core.js";

/**
 * Minimal structural cookie-store contract. Satisfied by the real next/headers
 * `cookies()` result (`ReadonlyRequestCookies`) and by `NextRequest.cookies`, and
 * trivially faked in tests without a Next.js request runtime — which is exactly
 * why `getTrustedContext`/`requireEntitledContext` take this instead of calling
 * `cookies()` internally.
 */
export interface CookieStore {
  get(name: string): { value: string } | undefined;
}

/**
 * Thrown by requireEntitledContext when the trusted user's org is not entitled to
 * this product. Carries the specific non-entitled status so callers (route
 * handlers) can respond appropriately. Server actions that don't catch it surface
 * a generic failure — which is a correct refusal (the UX path is the layout
 * access screen).
 */
export class EntitlementError extends Error {
  constructor(readonly entitlement: Exclude<Entitlement, "entitled">) {
    super(`Access required (${entitlement})`);
    this.name = "EntitlementError";
  }
}

export interface PlatformAccessNextOptions {
  /** The HMAC key for verifying access tokens (derive once from JWT_ACCESS_SECRET). */
  key: Uint8Array;
  /** Injectable seams (fetch/clock/apiBaseUrl) forwarded to every platform call — for tests. */
  deps?: ResolveDeps;
}

export interface PlatformAccessNext {
  /**
   * Server-side trusted context for the authenticated product surface.
   *
   * Reads the HttpOnly access-token cookie from the given store, verifies its
   * signature locally, and resolves the trusted orgId from the platform. This is
   * the ONLY identity source a server action / server component may trust before
   * touching org-scoped data — the JS-readable session-info cookie (read by the
   * proxy from `createProxy`) is UX-only and must never gate data.
   *
   * Returns null when there is no valid session or no active org membership. Use
   * `requireTrustedContext` when you want an automatic redirect to login instead.
   */
  getTrustedContext(store: CookieStore): Promise<TrustedContext | null>;

  /**
   * Like `getTrustedContext` but redirects to the portal login (with a `next`
   * back to this product) when no trusted context exists, so callers can treat
   * the return value as always-present.
   */
  requireTrustedContext(store: CookieStore): Promise<TrustedContext>;

  /**
   * The tenant-data security boundary: a trusted context that is ALSO entitled to
   * this product. Use at every server action / route handler / tenant-data page
   * loader. Redirects to login if there is no identity (via
   * requireTrustedContext); throws EntitlementError if identity is present but
   * not entitled.
   */
  requireEntitledContext(store: CookieStore): Promise<TrustedContext>;

  /**
   * Non-throwing entitlement lookup for the layout UX gate. Returns
   * "indeterminate" (never "none") when there is no readable/verifiable token,
   * so a transient problem never renders the upsell to a would-be payer.
   */
  getEntitlement(store: CookieStore): Promise<Entitlement>;

  /**
   * The verified identity (email + emailVerified) behind the session cookie, for a
   * product that needs to establish domain authorization from a company email.
   * Reads the HttpOnly access-token cookie, verifies it locally, then resolves the
   * platform's `GET /api/auth/me`. Returns null when there is no verifiable token or
   * the platform read fails closed — the caller falls back to an explicit ownership
   * challenge, never a security downgrade. This is NOT an identity boundary on its
   * own: gate tenant data with `requireEntitledContext`; use this only as an input to
   * establishing an ownership record.
   */
  getViewerIdentity(store: CookieStore): Promise<ViewerIdentity | null>;

  /**
   * Build the edge UX-gate middleware for this product: no session / expired
   * session -> bounce to the portal login with a `next` back to the request's
   * own path. This is UX gating from the JS-readable session-info cookie only —
   * real security is `requireEntitledContext`. `cfg.skip` can exempt paths that
   * the app's own middleware matcher doesn't already exclude.
   */
  createProxy(cfg?: {
    skip?: (pathname: string) => boolean;
  }): (req: NextRequest) => NextResponse;
}

/**
 * Bind a `PlatformAccessCore` (already parameterized with this product's
 * productCode/selfHost) to the Next.js request surface: cookie-reading trusted
 * context, entitlement gating, and the edge proxy. `key`/`deps` are supplied once
 * here so every call site only ever has to pass the cookie store.
 */
export function createPlatformAccessNext(
  core: PlatformAccessCore,
  opts: PlatformAccessNextOptions,
): PlatformAccessNext {
  const { key, deps } = opts;

  async function getTrustedContext(
    store: CookieStore,
  ): Promise<TrustedContext | null> {
    const token = store.get(ACCESS_COOKIE)?.value;
    return core.getTrustedContextFromToken(token, key, deps);
  }

  async function requireTrustedContext(
    store: CookieStore,
  ): Promise<TrustedContext> {
    const ctx = await getTrustedContext(store);
    if (ctx) return ctx;

    const host = (await headers()).get("host");
    redirect(core.portalLoginUrl(core.safeNextUrl(host, "/app")));
  }

  async function requireEntitledContext(
    store: CookieStore,
  ): Promise<TrustedContext> {
    const ctx = await requireTrustedContext(store); // redirects if no identity
    const token = store.get(ACCESS_COOKIE)?.value;
    const ent = token
      ? await core.getEntitlement(token, ctx.userId, deps)
      : "indeterminate";
    if (ent !== "entitled") throw new EntitlementError(ent);
    return ctx;
  }

  async function getEntitlement(store: CookieStore): Promise<Entitlement> {
    const token = store.get(ACCESS_COOKIE)?.value;
    if (!token) return "indeterminate";
    const user = await core.verifyAccessToken(token, key);
    if (!user) return "indeterminate";
    return core.getEntitlement(token, user.userId, deps);
  }

  async function getViewerIdentity(
    store: CookieStore,
  ): Promise<ViewerIdentity | null> {
    const token = store.get(ACCESS_COOKIE)?.value;
    if (!token) return null;
    const user = await core.verifyAccessToken(token, key);
    if (!user) return null;
    return core.resolveViewerIdentity(token, user.userId, deps);
  }

  function createProxy(cfg?: { skip?: (pathname: string) => boolean }) {
    return function proxy(req: NextRequest): NextResponse {
      if (cfg?.skip?.(req.nextUrl.pathname)) {
        return NextResponse.next();
      }

      const session = core.parseSessionInfo(
        req.cookies.get(SESSION_COOKIE)?.value,
      );

      if (!session) {
        // Build the public https return URL from the forwarded host (a proxy in
        // front of Next may terminate TLS, so req.nextUrl.protocol can't be
        // trusted). safeNextUrl fails closed on a spoofed/off-domain Host.
        const next = core.safeNextUrl(
          req.headers.get("host"),
          `${req.nextUrl.pathname}${req.nextUrl.search}`,
        );
        return NextResponse.redirect(core.portalLoginUrl(next));
      }

      return NextResponse.next();
    };
  }

  return {
    getTrustedContext,
    requireTrustedContext,
    requireEntitledContext,
    getEntitlement,
    getViewerIdentity,
    createProxy,
  };
}

import "server-only";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { NextResponse } from "next/server";
import { ACCESS_COOKIE, SESSION_COOKIE, } from "./core.js";
/**
 * Thrown by requireEntitledContext when the trusted user's org is not entitled to
 * this product. Carries the specific non-entitled status so callers (route
 * handlers) can respond appropriately. Server actions that don't catch it surface
 * a generic failure — which is a correct refusal (the UX path is the layout
 * access screen).
 */
export class EntitlementError extends Error {
    constructor(entitlement) {
        super(`Access required (${entitlement})`);
        this.entitlement = entitlement;
        this.name = "EntitlementError";
    }
}
/**
 * Bind a `PlatformAccessCore` (already parameterized with this product's
 * productCode/selfHost) to the Next.js request surface: cookie-reading trusted
 * context, entitlement gating, and the edge proxy. `key`/`deps` are supplied once
 * here so every call site only ever has to pass the cookie store.
 */
export function createPlatformAccessNext(core, opts) {
    const { key, deps } = opts;
    async function getTrustedContext(store) {
        const token = store.get(ACCESS_COOKIE)?.value;
        return core.getTrustedContextFromToken(token, key, deps);
    }
    async function requireTrustedContext(store) {
        const ctx = await getTrustedContext(store);
        if (ctx)
            return ctx;
        const host = (await headers()).get("host");
        redirect(core.portalLoginUrl(core.safeNextUrl(host, "/app")));
    }
    async function requireEntitledContext(store) {
        const ctx = await requireTrustedContext(store); // redirects if no identity
        const token = store.get(ACCESS_COOKIE)?.value;
        const ent = token
            ? await core.getEntitlement(token, ctx.userId, deps)
            : "indeterminate";
        if (ent !== "entitled")
            throw new EntitlementError(ent);
        return ctx;
    }
    async function getEntitlement(store) {
        const token = store.get(ACCESS_COOKIE)?.value;
        if (!token)
            return "indeterminate";
        const user = await core.verifyAccessToken(token, key);
        if (!user)
            return "indeterminate";
        return core.getEntitlement(token, user.userId, deps);
    }
    async function getViewerIdentity(store) {
        const token = store.get(ACCESS_COOKIE)?.value;
        if (!token)
            return null;
        const user = await core.verifyAccessToken(token, key);
        if (!user)
            return null;
        return core.resolveViewerIdentity(token, user.userId, deps);
    }
    function createProxy(cfg) {
        return function proxy(req) {
            if (cfg?.skip?.(req.nextUrl.pathname)) {
                return NextResponse.next();
            }
            const session = core.parseSessionInfo(req.cookies.get(SESSION_COOKIE)?.value);
            if (!session) {
                // Build the public https return URL from the forwarded host (a proxy in
                // front of Next may terminate TLS, so req.nextUrl.protocol can't be
                // trusted). safeNextUrl fails closed on a spoofed/off-domain Host.
                const next = core.safeNextUrl(req.headers.get("host"), `${req.nextUrl.pathname}${req.nextUrl.search}`);
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
//# sourceMappingURL=next.js.map
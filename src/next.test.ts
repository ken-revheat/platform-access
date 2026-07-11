import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";

import { createPlatformAccessCore } from "./core.js";
import {
  createPlatformAccessNext,
  EntitlementError,
  type CookieStore,
} from "./next.js";

const KEY = new TextEncoder().encode("test-secret-key-at-least-32-bytes-long");
const VALID_USER_ID = "9c858901-8a57-4791-81fe-4c455b099bc9";
const VALID_ORG_ID = "5b1f6a3e-7f2b-4e2a-9b1a-6f2c8a1d0e9f";

function signToken(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
    .sign(KEY);
}

/** A fake cookie store implementing the minimal CookieStore contract. */
function fakeCookieStore(values: Record<string, string>): CookieStore {
  return {
    get(name: string) {
      const value = values[name];
      return value === undefined ? undefined : { value };
    },
  };
}

describe("createPlatformAccessNext", () => {
  describe("requireEntitledContext", () => {
    it('throws EntitlementError with entitlement:"indeterminate" when resolveProducts is indeterminate', async () => {
      const core = createPlatformAccessCore({
        productCode: "quotafit",
        selfHost: "hire.revheat.com",
      });

      const token = await signToken({ userId: VALID_USER_ID });
      const store = fakeCookieStore({ revheat_access_token: token });

      // /api/org/me resolves cleanly (so a TrustedContext is established and no
      // redirect happens) but /api/me/products fails — the entitlement lookup
      // must come back "indeterminate", never "none".
      const fetchImpl = vi.fn(async (url: string | URL | Request) => {
        const href = typeof url === "string" ? url : url.toString();
        if (href.endsWith("/api/org/me")) {
          return new Response(
            JSON.stringify({ id: VALID_ORG_ID, name: "Acme Roofing" }),
            { status: 200 },
          );
        }
        if (href.endsWith("/api/me/products")) {
          return new Response("service unavailable", { status: 503 });
        }
        throw new Error(`unexpected fetch to ${href}`);
      });

      const next = createPlatformAccessNext(core, {
        key: KEY,
        deps: { fetchImpl: fetchImpl as unknown as typeof fetch },
      });

      await expect(next.requireEntitledContext(store)).rejects.toMatchObject(
        {
          entitlement: "indeterminate",
        },
      );

      // And it's specifically an EntitlementError, not some other rejection.
      let caught: unknown;
      try {
        await next.requireEntitledContext(store);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(EntitlementError);
      expect((caught as EntitlementError).entitlement).toBe("indeterminate");
    });

    it("resolves the trusted context when entitled", async () => {
      const core = createPlatformAccessCore({
        productCode: "quotafit",
        selfHost: "hire.revheat.com",
      });

      const token = await signToken({ userId: VALID_USER_ID });
      const store = fakeCookieStore({ revheat_access_token: token });

      const fetchImpl = vi.fn(async (url: string | URL | Request) => {
        const href = typeof url === "string" ? url : url.toString();
        if (href.endsWith("/api/org/me")) {
          return new Response(
            JSON.stringify({ id: VALID_ORG_ID, name: "Acme Roofing" }),
            { status: 200 },
          );
        }
        if (href.endsWith("/api/me/products")) {
          return new Response(
            JSON.stringify({
              products: [{ code: "quotafit", lockReason: null }],
            }),
            { status: 200 },
          );
        }
        throw new Error(`unexpected fetch to ${href}`);
      });

      const next = createPlatformAccessNext(core, {
        key: KEY,
        deps: { fetchImpl: fetchImpl as unknown as typeof fetch },
      });

      const ctx = await next.requireEntitledContext(store);
      expect(ctx).toEqual({
        userId: VALID_USER_ID,
        orgId: VALID_ORG_ID,
        orgName: "Acme Roofing",
      });
    });
  });

  describe("getTrustedContext", () => {
    it("returns null (no redirect attempted) when there is no access-token cookie", async () => {
      const core = createPlatformAccessCore({
        productCode: "quotafit",
        selfHost: "hire.revheat.com",
      });
      const store = fakeCookieStore({});
      const next = createPlatformAccessNext(core, { key: KEY });
      const ctx = await next.getTrustedContext(store);
      expect(ctx).toBeNull();
    });
  });
});

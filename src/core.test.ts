import { SignJWT } from "jose";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createPlatformAccessCore, type PlatformAccessCore } from "./core.js";

const KEY = new TextEncoder().encode("test-secret-key-at-least-32-bytes-long");
const VALID_USER_ID = "9c858901-8a57-4791-81fe-4c455b099bc9";

function signToken(
  claims: Record<string, unknown>,
  opts: { expSecondsFromNow?: number | null } = {},
): Promise<string> {
  const jwt = new SignJWT(claims).setProtectedHeader({ alg: "HS256" });
  const { expSecondsFromNow = 3600 } = opts;
  if (expSecondsFromNow !== null) {
    jwt.setExpirationTime(Math.floor(Date.now() / 1000) + expSecondsFromNow);
  }
  return jwt.sign(KEY);
}

function makeCore(overrides: Partial<Parameters<typeof createPlatformAccessCore>[0]> = {}): PlatformAccessCore {
  return createPlatformAccessCore({
    productCode: "quotafit",
    selfHost: "hire.revheat.com",
    apiBaseUrl: "https://api.revheat.com",
    portalUrl: "https://app.revheat.com",
    ...overrides,
  });
}

describe("createPlatformAccessCore", () => {
  let core: PlatformAccessCore;

  beforeEach(() => {
    core = makeCore();
  });

  describe("verifyAccessToken", () => {
    it("returns the trusted user for a valid token", async () => {
      const token = await signToken({ userId: VALID_USER_ID });
      const result = await core.verifyAccessToken(token, KEY);
      expect(result).toEqual({ userId: VALID_USER_ID });
    });

    it("returns null for an expired token", async () => {
      const token = await signToken(
        { userId: VALID_USER_ID },
        { expSecondsFromNow: -60 },
      );
      const result = await core.verifyAccessToken(token, KEY);
      expect(result).toBeNull();
    });

    it("returns null for a non-UUID userId", async () => {
      const token = await signToken({ userId: "not-a-uuid" });
      const result = await core.verifyAccessToken(token, KEY);
      expect(result).toBeNull();
    });

    it("returns null for a missing token", async () => {
      const result = await core.verifyAccessToken(undefined, KEY);
      expect(result).toBeNull();
    });

    it("returns null for a token signed with the wrong key", async () => {
      const wrongKey = new TextEncoder().encode("a-completely-different-secret-key");
      const token = await signToken({ userId: VALID_USER_ID }, {});
      const result = await core.verifyAccessToken(token, wrongKey);
      expect(result).toBeNull();
    });
  });

  describe("resolveProducts", () => {
    it("returns ok with parsed products on a clean 200", async () => {
      const fetchImpl = vi.fn(async () =>
        new Response(
          JSON.stringify({
            products: [
              { code: "quotafit", state: "active", lockReason: null, billingStatus: "current", appUrl: "https://hire.revheat.com" },
            ],
          }),
          { status: 200 },
        ),
      );
      const result = await core.resolveProducts(
        "token-abc",
        "user-1",
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      );
      expect(result).toEqual({
        status: "ok",
        products: [
          { code: "quotafit", state: "active", lockReason: null, billingStatus: "current", appUrl: "https://hire.revheat.com" },
        ],
      });
    });

    it("returns indeterminate (never none/null) on a non-200 response", async () => {
      const fetchImpl = vi.fn(async () => new Response("nope", { status: 500 }));
      const result = await core.resolveProducts(
        "token-abc",
        "user-2",
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      );
      expect(result).toEqual({ status: "indeterminate" });
      expect(result).not.toEqual({ status: "none" });
    });

    it("returns indeterminate (never none/null) when fetch throws (network error)", async () => {
      const fetchImpl = vi.fn(async () => {
        throw new Error("network unreachable");
      });
      const result = await core.resolveProducts(
        "token-abc",
        "user-3",
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      );
      expect(result).toEqual({ status: "indeterminate" });
      expect(result.status).not.toBe("none");
    });

    it("never caches an indeterminate result", async () => {
      let call = 0;
      const fetchImpl = vi.fn(async () => {
        call += 1;
        if (call === 1) throw new Error("transient failure");
        return new Response(JSON.stringify({ products: [] }), { status: 200 });
      });
      const deps = { fetchImpl: fetchImpl as unknown as typeof fetch };

      const first = await core.resolveProducts("token-abc", "user-4", deps);
      expect(first).toEqual({ status: "indeterminate" });

      const second = await core.resolveProducts("token-abc", "user-4", deps);
      expect(second).toEqual({ status: "ok", products: [] });
      expect(fetchImpl).toHaveBeenCalledTimes(2);
    });
  });

  describe("getEntitlement", () => {
    it("maps a transient resolveProducts failure to indeterminate, not none", async () => {
      const fetchImpl = vi.fn(async () => {
        throw new Error("timeout");
      });
      const entitlement = await core.getEntitlement(
        "token-abc",
        "user-5",
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      );
      expect(entitlement).toBe("indeterminate");
      expect(entitlement).not.toBe("none");
    });

    it("maps a non-200 platform response to indeterminate", async () => {
      const fetchImpl = vi.fn(async () => new Response("err", { status: 503 }));
      const entitlement = await core.getEntitlement(
        "token-abc",
        "user-6",
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      );
      expect(entitlement).toBe("indeterminate");
    });

    it("returns entitled when the product has no lockReason", async () => {
      const fetchImpl = vi.fn(async () =>
        new Response(
          JSON.stringify({ products: [{ code: "quotafit", lockReason: null }] }),
          { status: 200 },
        ),
      );
      const entitlement = await core.getEntitlement(
        "token-abc",
        "user-7",
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      );
      expect(entitlement).toBe("entitled");
    });

    it("returns locked when the product has a lockReason", async () => {
      const fetchImpl = vi.fn(async () =>
        new Response(
          JSON.stringify({ products: [{ code: "quotafit", lockReason: "past_due" }] }),
          { status: 200 },
        ),
      );
      const entitlement = await core.getEntitlement(
        "token-abc",
        "user-8",
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      );
      expect(entitlement).toBe("locked");
    });

    it("returns none when the configured productCode is absent from a clean response", async () => {
      const fetchImpl = vi.fn(async () =>
        new Response(JSON.stringify({ products: [{ code: "some-other-product", lockReason: null }] }), {
          status: 200,
        }),
      );
      const entitlement = await core.getEntitlement(
        "token-abc",
        "user-9",
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      );
      expect(entitlement).toBe("none");
    });

    it("uses the factory's configured productCode, not a hardcoded constant", async () => {
      const laCore = makeCore({ productCode: "lead-accelerator", selfHost: "leads.revheat.com" });
      const fetchImpl = vi.fn(async () =>
        new Response(
          JSON.stringify({
            products: [
              { code: "quotafit", lockReason: null },
              { code: "lead-accelerator", lockReason: null },
            ],
          }),
          { status: 200 },
        ),
      );
      const entitlement = await laCore.getEntitlement(
        "token-abc",
        "user-10",
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      );
      expect(entitlement).toBe("entitled");
    });
  });

  describe("safeNextUrl", () => {
    it("falls back to selfHost for an off-domain Host header", () => {
      const url = core.safeNextUrl("evil.example.com", "/app?x=1");
      expect(url).toBe("https://hire.revheat.com/app?x=1");
    });

    it("falls back to selfHost for a null Host header", () => {
      const url = core.safeNextUrl(null, "/app");
      expect(url).toBe("https://hire.revheat.com/app");
    });

    it("honours a .revheat.com Host header", () => {
      const url = core.safeNextUrl("leads.revheat.com", "/dashboard");
      expect(url).toBe("https://leads.revheat.com/dashboard");
    });

    it("uses the factory-configured selfHost, not a hardcoded product", () => {
      const laCore = makeCore({ productCode: "lead-accelerator", selfHost: "leads.revheat.com" });
      const url = laCore.safeNextUrl("evil.example.com", "/app");
      expect(url).toBe("https://leads.revheat.com/app");
    });
  });

  describe("parseSessionInfo", () => {
    const baseSession = {
      userId: VALID_USER_ID,
      orgId: "org-1",
      email: "a@b.com",
      productCodes: ["quotafit"],
    };

    it("treats expiresAt as milliseconds (a near-future ms timestamp is valid)", () => {
      const expiresAt = Date.now() + 60_000; // 1 minute from now, in ms
      const raw = JSON.stringify({ ...baseSession, expiresAt });
      const result = core.parseSessionInfo(raw);
      expect(result).toEqual({ ...baseSession, expiresAt });
    });

    it("rejects a session whose ms expiresAt is already in the past", () => {
      const expiresAt = Date.now() - 1000;
      const raw = JSON.stringify({ ...baseSession, expiresAt });
      const result = core.parseSessionInfo(raw);
      expect(result).toBeNull();
    });

    it("would incorrectly accept a seconds-epoch value if not treated as ms (guards against ×1000 regression)", () => {
      // A seconds-since-epoch timestamp for "now" is numerically far smaller than
      // Date.now() (ms) and so is correctly rejected as already-expired when
      // interpreted as ms — proving expiresAt is NOT scaled by 1000 anywhere.
      const secondsEpochNow = Math.floor(Date.now() / 1000);
      const raw = JSON.stringify({ ...baseSession, expiresAt: secondsEpochNow });
      const result = core.parseSessionInfo(raw);
      expect(result).toBeNull();
    });

    it("returns null for missing input", () => {
      expect(core.parseSessionInfo(null)).toBeNull();
      expect(core.parseSessionInfo(undefined)).toBeNull();
    });

    it("returns null for malformed JSON", () => {
      expect(core.parseSessionInfo("{not json")).toBeNull();
    });

    it("tolerates a URL-encoded JSON payload without double-decoding", () => {
      const expiresAt = Date.now() + 60_000;
      const raw = encodeURIComponent(JSON.stringify({ ...baseSession, expiresAt }));
      const result = core.parseSessionInfo(raw);
      expect(result).toEqual({ ...baseSession, expiresAt });
    });
  });

  describe("resolveOrg", () => {
    it("returns null on a non-200 response (fail closed)", async () => {
      const fetchImpl = vi.fn(async () => new Response("nope", { status: 401 }));
      const result = await core.resolveOrg("token-abc", "user-11", {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      expect(result).toBeNull();
    });

    it("returns null when fetch throws", async () => {
      const fetchImpl = vi.fn(async () => {
        throw new Error("dns failure");
      });
      const result = await core.resolveOrg("token-abc", "user-12", {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      expect(result).toBeNull();
    });

    it("resolves a trusted org from a clean 200", async () => {
      const orgId = "5b1f6a3e-7f2b-4e2a-9b1a-6f2c8a1d0e9f";
      const fetchImpl = vi.fn(async () =>
        new Response(JSON.stringify({ id: orgId, name: "Acme Roofing" }), { status: 200 }),
      );
      const result = await core.resolveOrg("token-abc", "user-13", {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      expect(result).toEqual({ orgId, orgName: "Acme Roofing" });
    });
  });

  describe("portalLoginUrl", () => {
    it("builds a login URL against the configured portalUrl with an encoded next", () => {
      const url = core.portalLoginUrl("https://hire.revheat.com/app");
      expect(url).toBe(
        "https://app.revheat.com/login?next=https%3A%2F%2Fhire.revheat.com%2Fapp",
      );
    });
  });
});

// Test-only stand-in for the "server-only" package. Next's bundler turns that
// package's guard into a no-op inside Server Component/server bundles (which is
// exactly the context next.ts always runs in); vitest has no such bundler
// condition and the real package throws unconditionally on plain Node import.
// This alias (see vitest.config.ts) reproduces the bundler's no-op behavior so
// next.test.ts can exercise next.ts without a Next.js runtime.
export {};

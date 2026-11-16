// The mirror's only writer. The static files are served straight from the R2 bucket at
// https://maven.quickskin.net/; this Worker is the one way anything gets into that bucket.
//
// It holds no secret. A caller proves it is the Publish workflow of this repository, on main and
// on a GitHub-hosted runner, with the OpenID Connect token GitHub Actions issues to that job; the
// token is checked against GitHub's published keys on every request. A file is stored under the
// sha256 its caller names, which R2 itself verifies against the bytes, and a file that is there is
// never replaced: only the generated listings (maven-metadata.xml, the manifest and the index
// page) may change. Nothing is ever deleted through here.

export interface StoredObject {
  customMetadata?: Record<string, string>;
}

export interface Bucket {
  head(key: string): Promise<StoredObject | null>;
  put(key: string, body: ReadableStream | ArrayBuffer | null, options: {
    sha256?: string;
    httpMetadata?: { contentType?: string; cacheControl?: string };
    customMetadata?: Record<string, string>;
  }): Promise<unknown>;
}

export interface Env {
  BUCKET: Bucket;
  /** The audience the workflow asks its token for. */
  AUDIENCE: string;
  /** Numeric ids, which a rename or a transfer of the repository cannot imitate. */
  REPOSITORY_ID: string;
  OWNER_ID: string;
  /** The one workflow file, at the one ref, whose jobs may write. */
  WORKFLOW_REF: string;
}

export interface Jwk {
  kid?: string;
  kty?: string;
  [key: string]: unknown;
}

export interface Deps {
  /** Seconds since the epoch. */
  now(): number;
  /** GitHub's current signing keys. */
  keys(): Promise<Jwk[]>;
}

export const ISSUER = "https://token.actions.githubusercontent.com";
const KEYS_URL = `${ISSUER}/.well-known/jwks`;
const KEYS_SECONDS = 600;
const CLOCK_SKEW = 60;
/** The largest request body a Worker accepts. */
export const MAX_BYTES = 100 * 1024 * 1024;
const EVENTS = new Set(["push", "schedule", "workflow_dispatch"]);

const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;
const SIDECAR = /\.(md5|sha1|sha256|sha512)$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ROOT_FILES = new Set(["mirror-manifest.json", "index.html"]);
const LISTING = "maven-metadata.xml";

class Refusal extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function answer(status: number, data: Record<string, unknown>): Response {
  return new Response(JSON.stringify(data) + "\n", {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function decode(part: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) throw new Refusal(401, "malformed token");
  const base64 = part.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (part.length % 4)) % 4);
  const text = atob(base64);
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i);
  return bytes;
}

function object(bytes: Uint8Array<ArrayBuffer>): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Refusal(401, "malformed token");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Refusal(401, "malformed token");
  return value as Record<string, unknown>;
}

let cached: { keys: Jwk[]; until: number } | null = null;

async function fetchKeys(): Promise<Jwk[]> {
  const response = await fetch(KEYS_URL, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Refusal(503, "GitHub's signing keys could not be read");
  const body = (await response.json()) as { keys?: Jwk[] };
  if (!Array.isArray(body.keys)) throw new Refusal(503, "GitHub's signing keys could not be read");
  return body.keys;
}

export const live: Deps = {
  now: () => Math.floor(Date.now() / 1000),
  async keys() {
    const now = Math.floor(Date.now() / 1000);
    if (cached === null || cached.until <= now) cached = { keys: await fetchKeys(), until: now + KEYS_SECONDS };
    return cached.keys;
  },
};

/** The claims of the token, once it is known to be GitHub's and to belong to the Publish workflow on main. */
export async function publisher(request: Request, env: Env, deps: Deps): Promise<Record<string, unknown>> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) throw new Refusal(401, "a GitHub Actions OpenID Connect token is required");
  const parts = header.slice(7).split(".");
  if (parts.length !== 3) throw new Refusal(401, "malformed token");
  const head = object(decode(parts[0]));
  const claims = object(decode(parts[1]));
  if (head.alg !== "RS256" || typeof head.kid !== "string") throw new Refusal(401, "unsupported token");
  const jwk = (await deps.keys()).find((key) => key.kid === head.kid && key.kty === "RSA");
  if (jwk === undefined) throw new Refusal(401, "the token is signed with a key GitHub does not publish");
  let valid = false;
  try {
    const key = await crypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false, ["verify"]);
    valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decode(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  } catch {
    valid = false;
  }
  if (!valid) throw new Refusal(401, "the token's signature is not GitHub's");

  const now = deps.now();
  const number = (name: string): number => {
    const value = claims[name];
    if (typeof value !== "number" || !Number.isFinite(value)) throw new Refusal(401, `the token has no ${name}`);
    return value;
  };
  if (number("exp") <= now) throw new Refusal(401, "the token has expired");
  if (number("iat") > now + CLOCK_SKEW) throw new Refusal(401, "the token is not valid yet");
  if (typeof claims.nbf === "number" && claims.nbf > now + CLOCK_SKEW) throw new Refusal(401, "the token is not valid yet");
  const expected: Record<string, string> = {
    iss: ISSUER,
    aud: env.AUDIENCE,
    repository_id: env.REPOSITORY_ID,
    repository_owner_id: env.OWNER_ID,
    job_workflow_ref: env.WORKFLOW_REF,
    workflow_ref: env.WORKFLOW_REF,
    ref: env.WORKFLOW_REF.slice(env.WORKFLOW_REF.indexOf("@") + 1),
    runner_environment: "github-hosted",
  };
  for (const [name, value] of Object.entries(expected)) {
    if (value === "" || claims[name] !== value) throw new Refusal(403, `the token's ${name} may not publish here`);
  }
  if (typeof claims.event_name !== "string" || !EVENTS.has(claims.event_name)) {
    throw new Refusal(403, "the token's event_name may not publish here");
  }
  return claims;
}

export interface Target {
  key: string;
  /** Whether what is stored there may be replaced: only the generated listings. */
  mutable: boolean;
}

/** The bucket key a request path names, or null when it is not a path of the mirror. */
export function target(path: string): Target | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return null;
  }
  const segments = decoded.split("/");
  if (segments.length > 40 || decoded.length > 1024 || !segments.every((segment) => SEGMENT.test(segment))) return null;
  const file = segments[segments.length - 1].replace(SIDECAR, "");
  if (segments.length === 1) return ROOT_FILES.has(decoded) ? { key: decoded, mutable: true } : null;
  if (file === LISTING) return segments.length >= 3 ? { key: decoded, mutable: true } : null;
  // group (one segment or more) / name / version / file
  return segments.length >= 4 ? { key: decoded, mutable: false } : null;
}

function contentType(key: string): string {
  if (SIDECAR.test(key)) return "text/plain; charset=us-ascii";
  if (key.endsWith(".jar") || key.endsWith(".zip")) return "application/java-archive";
  if (key.endsWith(".pom") || key.endsWith(".xml")) return "application/xml";
  if (key.endsWith(".module") || key.endsWith(".json")) return "application/json";
  if (key.endsWith(".html")) return "text/html; charset=utf-8";
  return "application/octet-stream";
}

async function store(request: Request, env: Env, claims: Record<string, unknown>, to: Target): Promise<Response> {
  const sha = request.headers.get("x-sha256") ?? "";
  if (!HEX64.test(sha)) throw new Refusal(400, "x-sha256 must be the file's sha256 in lower-case hex");
  const length = request.headers.get("content-length") ?? "";
  if (!/^(0|[1-9][0-9]{0,11})$/.test(length)) throw new Refusal(411, "content-length is required");
  if (Number(length) > MAX_BYTES) throw new Refusal(413, `a file may be at most ${MAX_BYTES} bytes`);
  const existing = await env.BUCKET.head(to.key);
  if (existing !== null) {
    const held = existing.customMetadata?.sha256;
    if (held === sha) return answer(200, { status: "present", key: to.key, sha256: sha });
    if (!to.mutable) throw new Refusal(409, `${to.key} is already published with other bytes (sha256 ${held ?? "unknown"})`);
  }
  try {
    await env.BUCKET.put(to.key, request.body, {
      sha256: sha,
      httpMetadata: {
        contentType: contentType(to.key),
        cacheControl: to.mutable ? "public, max-age=300" : "public, max-age=31536000, immutable",
      },
      customMetadata: { sha256: sha, run: String(claims.run_id ?? ""), commit: String(claims.sha ?? "") },
    });
  } catch {
    throw new Refusal(422, `${to.key} was not stored: the bytes sent do not have the sha256 named`);
  }
  return answer(201, { status: "stored", key: to.key, sha256: sha });
}

export async function handle(request: Request, env: Env, deps: Deps = live): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (url.pathname === "/" && request.method === "GET") {
      return answer(200, { service: "Plum Maven Mirror publisher", mirror: env.AUDIENCE });
    }
    if (url.pathname === "/v1/whoami" && request.method === "GET") {
      const claims = await publisher(request, env, deps);
      return answer(200, { publisher: true, run: claims.run_id ?? null, commit: claims.sha ?? null });
    }
    if (url.pathname.startsWith("/v1/files/")) {
      if (request.method !== "PUT") throw new Refusal(405, "files are published with PUT");
      const claims = await publisher(request, env, deps);
      const to = target(url.pathname.slice("/v1/files/".length));
      if (to === null) throw new Refusal(400, "not a path of the mirror");
      return await store(request, env, claims, to);
    }
    throw new Refusal(404, "not found");
  } catch (error) {
    if (error instanceof Refusal) return answer(error.status, { error: error.message });
    return answer(500, { error: "internal" });
  }
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, env);
  },
};

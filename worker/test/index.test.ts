import assert from "node:assert/strict";
import { test } from "node:test";
import { type Bucket, type Deps, type Env, handle, ISSUER, MAX_BYTES, target } from "../src/index.ts";

const WORKFLOW = "The-Plum-Team/maven-mirror/.github/workflows/publish.yml@refs/heads/main";
const NOW = 1_800_000_000;

function b64url(bytes: Uint8Array | string): string {
  const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  return Buffer.from(data).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(bytes: Uint8Array): Promise<string> {
  return Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex");
}

interface World {
  env: Env;
  deps: Deps;
  objects: Map<string, { bytes: Uint8Array; meta: Record<string, string>; cache: string }>;
  token(changes?: Record<string, unknown>, kid?: string): Promise<string>;
  put(path: string, bytes: Uint8Array, headers?: Record<string, string>): Promise<Response>;
}

async function world(): Promise<World> {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"]);
  const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "k1" };
  const objects: World["objects"] = new Map();
  const bucket: Bucket = {
    async head(key) {
      const held = objects.get(key);
      return held ? { customMetadata: held.meta } : null;
    },
    async put(key, body, options) {
      const bytes = body === null ? new Uint8Array() : new Uint8Array(await new Response(body as ReadableStream).arrayBuffer());
      // R2 refuses a body that does not have the sha256 it was told to expect
      if (options.sha256 !== undefined && options.sha256 !== await sha256(bytes)) throw new Error("sha256 mismatch");
      objects.set(key, { bytes, meta: options.customMetadata ?? {}, cache: options.httpMetadata?.cacheControl ?? "" });
      return {};
    },
  };
  const env: Env = { BUCKET: bucket, AUDIENCE: "https://maven.example", REPOSITORY_ID: "42", OWNER_ID: "7", WORKFLOW_REF: WORKFLOW };
  const deps: Deps = { now: () => NOW, keys: async () => [jwk] };
  const claims = {
    iss: ISSUER, aud: env.AUDIENCE, exp: NOW + 300, iat: NOW - 5, nbf: NOW - 5,
    repository: "The-Plum-Team/maven-mirror", repository_id: "42", repository_owner_id: "7",
    ref: "refs/heads/main", workflow_ref: WORKFLOW, job_workflow_ref: WORKFLOW,
    event_name: "schedule", runner_environment: "github-hosted", run_id: "9001", sha: "a".repeat(40),
  };
  async function token(changes: Record<string, unknown> = {}, kid = "k1"): Promise<string> {
    const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
    const body = b64url(JSON.stringify({ ...claims, ...changes }));
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(`${head}.${body}`));
    return `${head}.${body}.${b64url(new Uint8Array(signature))}`;
  }
  async function put(path: string, bytes: Uint8Array, headers: Record<string, string> = {}): Promise<Response> {
    const all: Record<string, string> = {
      authorization: `Bearer ${await token()}`, "x-sha256": await sha256(bytes), "content-length": String(bytes.length), ...headers,
    };
    for (const [name, value] of Object.entries(all)) if (value === "") delete all[name];
    return handle(new Request(`https://upload.example/v1/files/${path}`, { method: "PUT", headers: all, body: bytes }), env, deps);
  }
  return { env, deps, objects, token, put };
}

const JAR = "org/example/lib/1.0+build.2/lib-1.0+build.2.jar";
const bytes = (text: string) => new TextEncoder().encode(text);

test("a file from the publish workflow is stored once and never replaced", async () => {
  const w = await world();
  const first = await w.put(JAR, bytes("one"));
  assert.equal(first.status, 201);
  assert.deepEqual(w.objects.get(JAR)?.bytes, bytes("one"));
  assert.equal(w.objects.get(JAR)?.meta.run, "9001");
  assert.match(w.objects.get(JAR)!.cache, /immutable/);
  const again = await w.put(JAR, bytes("one"));
  assert.equal(again.status, 200);
  assert.equal((await again.json() as { status: string }).status, "present");
  const other = await w.put(JAR, bytes("two"));
  assert.equal(other.status, 409);
  assert.deepEqual(w.objects.get(JAR)?.bytes, bytes("one"));
  // Its checksum files are as fixed as it is
  assert.equal((await w.put(`${JAR}.sha1`, bytes("aa"))).status, 201);
  assert.equal((await w.put(`${JAR}.sha1`, bytes("bb"))).status, 409);
});

test("the generated listings may change", async () => {
  const w = await world();
  for (const path of ["org/example/lib/maven-metadata.xml", "org/example/lib/maven-metadata.xml.sha256", "mirror-manifest.json", "index.html"]) {
    assert.equal((await w.put(path, bytes("v1"))).status, 201, path);
    assert.equal((await w.put(path, bytes("v2"))).status, 201, path);
    assert.deepEqual(w.objects.get(path)?.bytes, bytes("v2"));
    assert.doesNotMatch(w.objects.get(path)!.cache, /immutable/);
  }
});

test("bytes that do not have the sha256 named are not stored", async () => {
  const w = await world();
  const response = await w.put(JAR, bytes("one"), { "x-sha256": "0".repeat(64) });
  assert.equal(response.status, 422);
  assert.equal(w.objects.size, 0);
  assert.equal((await w.put(JAR, bytes("one"), { "x-sha256": "XYZ" })).status, 400);
  assert.equal((await w.put(JAR, bytes("one"), { "content-length": String(MAX_BYTES + 1) })).status, 413);
});

test("only paths of a Maven mirror are accepted", () => {
  for (const good of [JAR, `${JAR}.md5`, "a/b/maven-metadata.xml", "a/b/c/d/e/f-1.pom", "index.html", "mirror-manifest.json"]) {
    assert.notEqual(target(good), null, good);
  }
  for (const bad of ["", "x.jar", "a/b.jar", "a/b/c.jar", "a/../b/c/d.jar", "a/.b/c/d.jar", "a//b/c/d.jar", "/a/b/c/d.jar",
    "a/b/c/d.jar/", "a/b/c/d%2F..%2Fe.jar", "a/b/c/d e.jar", "a/b/c/%E0%A4%A", "maven-metadata.xml", "a/maven-metadata.xml",
    "robots.txt", "a/b/c/d\\e.jar"]) {
    assert.equal(target(bad), null, bad);
  }
  assert.equal(target("a/b/maven-metadata.xml")?.mutable, true);
  assert.equal(target(JAR)?.mutable, false);
  assert.equal(target(encodeURIComponent("a") + "/b/c/" + encodeURIComponent("d+e.jar"))?.key, "a/b/c/d+e.jar");
});

test("nobody but the publish workflow on main may write", async () => {
  const w = await world();
  const attempt = async (authorization: string) => {
    const body = bytes("one");
    const response = await handle(new Request(`https://upload.example/v1/files/${JAR}`, {
      method: "PUT", body,
      headers: { authorization, "x-sha256": await sha256(body), "content-length": String(body.length) },
    }), w.env, w.deps);
    return response.status;
  };
  assert.equal(await attempt(""), 401);
  assert.equal(await attempt("Bearer nonsense"), 401);
  assert.equal(await attempt(`Bearer ${await w.token({}, "other-key")}`), 401);
  const good = await w.token();
  const [head, body, signature] = good.split(".");
  const forged = b64url(JSON.stringify({ ...JSON.parse(Buffer.from(body, "base64url").toString()), repository_id: "42", ref: "refs/heads/main" }));
  assert.equal(await attempt(`Bearer ${head}.${forged.slice(0, -2)}AA.${signature}`), 401);
  const none = `${b64url(JSON.stringify({ alg: "none", kid: "k1" }))}.${body}.`;
  assert.equal(await attempt(`Bearer ${none}`), 401);
  assert.equal(await attempt(`Bearer ${await w.token({ exp: NOW - 1 })}`), 401);
  assert.equal(await attempt(`Bearer ${await w.token({ iat: NOW + 3600 })}`), 401);
  for (const changes of [
    { aud: "https://github.com/The-Plum-Team" },
    { iss: "https://token.actions.githubusercontent.com/evil" },
    { repository_id: "43" },
    { repository_owner_id: "8" },
    { ref: "refs/heads/feature", workflow_ref: WORKFLOW.replace("main", "feature"), job_workflow_ref: WORKFLOW.replace("main", "feature") },
    { job_workflow_ref: "The-Plum-Team/maven-mirror/.github/workflows/check.yml@refs/heads/main" },
    { workflow_ref: "The-Plum-Team/maven-mirror/.github/workflows/check.yml@refs/heads/main" },
    { ref: "refs/pull/5/merge" },
    { event_name: "pull_request" },
    { event_name: "pull_request_target" },
    { runner_environment: "self-hosted" },
  ]) {
    assert.equal(await attempt(`Bearer ${await w.token(changes)}`), 403, JSON.stringify(changes));
  }
  assert.equal(w.objects.size, 0);
  assert.equal(await attempt(`Bearer ${good}`), 201);
});

test("there is no way to read, list or delete through the publisher", async () => {
  const w = await world();
  await w.put(JAR, bytes("one"));
  const authorization = `Bearer ${await w.token()}`;
  for (const method of ["GET", "DELETE", "POST", "HEAD"]) {
    const response = await handle(new Request(`https://upload.example/v1/files/${JAR}`, { method, headers: { authorization } }), w.env, w.deps);
    assert.equal(response.status, 405, method);
  }
  assert.equal(w.objects.size, 1);
  assert.equal((await handle(new Request("https://upload.example/v1/whoami", { headers: { authorization } }), w.env, w.deps)).status, 200);
  assert.equal((await handle(new Request("https://upload.example/v1/whoami"), w.env, w.deps)).status, 401);
  assert.equal((await handle(new Request("https://upload.example/v1/other"), w.env, w.deps)).status, 404);
});

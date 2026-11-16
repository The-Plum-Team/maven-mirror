import contextlib
import functools
import hashlib
import http.server
import io
import json
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import mirror  # noqa: E402

NS = "https://schema.gradle.org/dependency-verification"


def metadata(*components):
    body = []
    for group, name, version, files in components:
        artifacts = "".join(
            f'<artifact name="{f}"><sha256 value="{h}" origin="test"/></artifact>' for f, h in files
        )
        body.append(f'<component group="{group}" name="{name}" version="{version}">{artifacts}</component>')
    return f'<verification-metadata xmlns="{NS}"><components>{"".join(body)}</components></verification-metadata>'.encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@contextlib.contextmanager
def serve(directory: Path):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    handler.log_message = lambda *args: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = mirror.Policy.load()

    def test_mojang_and_minecraft_are_never_mirrored(self):
        for group, name in [("com.mojang", "brigadier"), ("net.minecraft", "client"),
                            ("org.lwjgl", "lwjgl-freetype"), ("de.oceanlabs.mcp", "mcp_config"),
                            ("net.neoforged", "neoform")]:
            self.assertEqual(self.policy.classify(group, name)[0], "exclude", (group, name))

    def test_central_artifacts_are_left_to_the_license_their_pom_declares(self):
        self.assertEqual(self.policy.classify("com.google.guava", "guava")[0], "uncovered")
        self.assertEqual(self.policy.by_pom.upstreams, ("google-central", "central", "gradle-plugins"))

    def test_the_licenses_central_poms_declare_are_recognised(self):
        rule = self.policy.by_pom
        for name, label in [("Apache License, Version 2.0", "Apache-2.0"), ("Apache-2.0", "Apache-2.0"),
                            ("The Apache Software License, Version 2.0", "Apache-2.0"), ("Apache 2", "Apache-2.0"),
                            ("MIT License", "MIT"), ("SPDX-License-Identifier: MIT", "MIT"),
                            ("BSD-3-Clause", "BSD"), ("The BSD License", "BSD"), ("0BSD", "BSD"),
                            ("Eclipse Distribution License - v 1.0", "BSD"),
                            ("Eclipse Public License v2.0", "EPL"),
                            ("GNU Lesser General Public License v3.0", "LGPL"), ("LGPL-2.1-or-later", "LGPL"),
                            ("Mozilla Public License Version 2.0", "MPL-2.0"), ("Unicode/ICU License", "Unicode"),
                            ("Dual license consisting of the CDDL v1.1 and GPL v2", "CDDL"),
                            ("Bouncy Castle Licence", "Bouncy-Castle"), ("Public Domain", "Public-Domain")]:
            self.assertEqual(rule.recognise([(name, "")]), [label], name)
        self.assertEqual(rule.recognise([("", "https://www.apache.org/licenses/LICENSE-2.0.txt")]), ["Apache-2.0"])
        for name in ["GPL v2 with the Classpath exception", "GNU General Public License, version 2",
                     "Similar to Apache License but with the acknowledgment clause removed",
                     "Commercial", "All rights reserved", "You may not permit redistribution"]:
            self.assertEqual(rule.recognise([(name, "")]), [], name)
        # Several licenses are a choice among them
        self.assertEqual(rule.recognise([("GPL v2 with the Classpath exception", ""), ("The MIT License", "")]), ["MIT"])

    def test_every_include_rule_names_a_license(self):
        for rule in self.policy.include:
            self.assertTrue(rule.license and rule.upstreams)


class ListTest(unittest.TestCase):
    def test_conflicting_hashes_exclude_the_component(self):
        policy = mirror.Policy.load()
        a = metadata(("net.fabricmc", "fabric-loader", "1.0", [("fabric-loader-1.0.jar", "a" * 64)]))
        b = metadata(("net.fabricmc", "fabric-loader", "1.0", [("fabric-loader-1.0.jar", "b" * 64)]),
                     ("net.fabricmc", "fabric-loader", "2.0", [("fabric-loader-2.0.jar", "c" * 64)]))
        entries, excluded, _ = mirror.build_list(policy, [("a", a), ("b", b)])
        self.assertEqual([e.path for e in entries], ["net/fabricmc/fabric-loader/2.0/fabric-loader-2.0.jar"])
        self.assertIn("net.fabricmc:fabric-loader:1.0", excluded)

    def test_module_declared_files_are_added_with_their_declared_hashes(self):
        base = "net/neoforged/neoforge/1.0"
        module = json.dumps({"variants": [
            {"name": "runtime", "files": [{"url": "neoforge-1.0-universal.jar", "sha256": "a" * 64}]},
            {"name": "sources", "files": [{"url": "neoforge-1.0-sources.jar", "sha256": "b" * 64}]},
            {"name": "javadoc", "files": [{"url": "neoforge-1.0-javadoc.jar", "sha256": "c" * 64}]},
            {"name": "elsewhere", "available-at": {"url": "../../x/1.0/x-1.0.module"}},
        ]}).encode()
        entries = [mirror.Entry(f"{base}/neoforge-1.0.module", (sha(module),), ("neoforged",), "LGPL-2.1"),
                   mirror.Entry(f"{base}/neoforge-1.0-universal.jar", ("a" * 64,), ("neoforged",), "LGPL-2.1")]
        added = mirror.module_declared(entries, lambda entry: module)
        self.assertEqual([(e.path, e.hashes, e.license) for e in added],
                         [(f"{base}/neoforge-1.0-sources.jar", ("b" * 64,), "LGPL-2.1")])

    def test_module_with_unsafe_file_url_is_rejected(self):
        module = json.dumps({"variants": [{"files": [{"url": "..", "sha256": "a" * 64}]}]}).encode()
        entries = [mirror.Entry("net/fabricmc/x/1.0/x-1.0.module", (sha(module),), ("fabric",), "MIT")]
        with self.assertRaises(mirror.MirrorError):
            mirror.module_declared(entries, lambda entry: module)

    def test_unsafe_paths_are_rejected(self):
        with self.assertRaises(mirror.MirrorError):
            mirror.check_path("net/fabricmc/../x/1/x-1.jar")


def pom(licenses=(), parent=None, namespace=True):
    xmlns = ' xmlns="http://maven.apache.org/POM/4.0.0"' if namespace else ""
    body = ""
    if parent:
        body += "<parent><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version></parent>" % parent
    if licenses:
        body += "<licenses>" + "".join(f"<license><name>{name}</name><url>{url}</url></license>"
                                       for name, url in licenses) + "</licenses>"
    return f'<?xml version="1.0"?><project{xmlns}>{body}</project>'.encode()


class PomLicenseTest(unittest.TestCase):
    """What `by_pom` mirrors is decided by the POMs an upstream serves."""

    def decide(self, files, components, gavs):
        with tempfile.TemporaryDirectory() as work:
            for path, data in files.items():
                (Path(work) / path).parent.mkdir(parents=True, exist_ok=True)
                (Path(work) / path).write_bytes(data)
            documents = [("test", metadata(*components))]
            with serve(Path(work)) as url:
                policy = mirror.Policy.load()
                policy.upstreams = {**policy.upstreams, **{key: url for key in policy.by_pom.upstreams}}
                poms = mirror.Poms(policy, mirror.recorded_files(documents), [], jobs=2)
                entries, excluded, uncovered = mirror.build_list(policy, documents, poms)
            return ({gav: poms.decide(gav) for gav in gavs}, {e.path: e for e in entries}, excluded, uncovered)

    def test_a_declared_open_license_mirrors_the_component_from_central(self):
        own = pom([("Apache License, Version 2.0", "")])
        decisions, entries, excluded, _ = self.decide(
            {"org/example/lib/1.0/lib-1.0.pom": own},
            [("org.example", "lib", "1.0", [("lib-1.0.pom", sha(own)), ("lib-1.0.jar", "a" * 64)])],
            [("org.example", "lib", "1.0")])
        self.assertEqual(decisions[("org.example", "lib", "1.0")], ("Apache-2.0", ""))
        entry = entries["org/example/lib/1.0/lib-1.0.jar"]
        self.assertEqual((entry.license, entry.upstreams), ("Apache-2.0", ("google-central", "central", "gradle-plugins")))
        self.assertEqual(excluded, {})

    def test_the_license_may_come_from_a_parent_and_a_parent_alone_is_metadata(self):
        parent = pom(namespace=False)
        grand = pom([("MIT License", "")])
        child = pom(parent=("org.example", "parent", "7"))
        licensed = pom(parent=("org.example", "licensed-parent", "3"))
        decisions, entries, excluded, _ = self.decide(
            {"org/example/parent/7/parent-7.pom": parent,
             "org/example/licensed-parent/3/licensed-parent-3.pom": grand,
             "org/example/orphan/1.0/orphan-1.0.pom": child,
             "org/example/lib/1.0/lib-1.0.pom": licensed},
            [("org.example", "parent", "7", [("parent-7.pom", sha(parent))]),
             ("org.example", "orphan", "1.0", [("orphan-1.0.pom", sha(child)), ("orphan-1.0.jar", "a" * 64)]),
             ("org.example", "lib", "1.0", [("lib-1.0.pom", sha(licensed)), ("lib-1.0.jar", "b" * 64)])],
            [("org.example", "parent", "7"), ("org.example", "orphan", "1.0"), ("org.example", "lib", "1.0")])
        self.assertEqual(decisions[("org.example", "lib", "1.0")], ("MIT", ""))
        self.assertEqual(decisions[("org.example", "parent", "7")], ("metadata-only", ""))
        self.assertEqual(decisions[("org.example", "orphan", "1.0")], ("", "no license in its POM or its parents"))
        self.assertIn("org/example/parent/7/parent-7.pom", entries)
        self.assertNotIn("org/example/orphan/1.0/orphan-1.0.jar", entries)
        self.assertEqual(excluded, {"org.example:orphan:1.0": "no license in its POM or its parents"})

    def test_an_unrecognised_license_or_a_missing_pom_stays_on_its_upstream(self):
        closed = pom([("Proprietary", "https://example.com/terms")])
        decisions, entries, excluded, _ = self.decide(
            {"org/example/closed/1.0/closed-1.0.pom": closed},
            [("org.example", "closed", "1.0", [("closed-1.0.pom", sha(closed)), ("closed-1.0.jar", "a" * 64)]),
             ("org.elsewhere", "hosted", "1.0", [("hosted-1.0.jar", "b" * 64)])],
            [("org.example", "closed", "1.0"), ("org.elsewhere", "hosted", "1.0")])
        self.assertEqual(decisions[("org.example", "closed", "1.0")][0], "")
        self.assertIn("Proprietary", decisions[("org.example", "closed", "1.0")][1])
        self.assertEqual(decisions[("org.elsewhere", "hosted", "1.0")],
                         ("", "no POM on Maven Central or the Gradle Plugin Portal"))
        self.assertEqual(entries, {})
        self.assertEqual(sorted(excluded), ["org.elsewhere:hosted:1.0", "org.example:closed:1.0"])

    def test_a_pom_that_is_not_the_one_the_mods_record_stops_the_run(self):
        own = pom([("MIT License", "")])
        with self.assertRaises(mirror.MirrorError):
            self.decide({"org/example/lib/1.0/lib-1.0.pom": own},
                        [("org.example", "lib", "1.0", [("lib-1.0.pom", "f" * 64), ("lib-1.0.jar", "a" * 64)])], [])

    def test_explicit_rules_and_exclusions_come_before_the_pom(self):
        own = pom([("Apache License, Version 2.0", "")])
        _, entries, excluded, _ = self.decide(
            {"com/mojang/brigadier/1.0/brigadier-1.0.pom": own},
            [("com.mojang", "brigadier", "1.0", [("brigadier-1.0.pom", sha(own)), ("brigadier-1.0.jar", "a" * 64)]),
             ("net.fabricmc", "fabric-loader", "1.0", [("fabric-loader-1.0.jar", "b" * 64)])], [])
        self.assertEqual(list(entries), ["net/fabricmc/fabric-loader/1.0/fabric-loader-1.0.jar"])
        self.assertEqual(entries["net/fabricmc/fabric-loader/1.0/fabric-loader-1.0.jar"].upstreams, ("fabric",))
        self.assertIn("com.mojang:brigadier:1.0", excluded)

    def test_a_pom_with_a_document_type_is_not_read(self):
        with self.assertRaises(mirror.MirrorError):
            mirror.read_pom(b'<?xml version="1.0"?><!DOCTYPE project [<!ENTITY a "b">]><project/>')
        self.assertEqual(mirror.read_pom(pom(parent=("g", "a", "${revision}"))), ([], None))


class CompletedVersionsTest(unittest.TestCase):
    """A POM-only version gets the other jars its upstream lists, so no machine finds half of it here."""
    UPSTREAMS = ("google-central", "central", "gradle-plugins")
    BASE = "org/lwjgl/lwjgl/3.3.2"

    def entries(self, *names, upstreams=None):
        return [mirror.Entry(f"{self.BASE}/{name}", (sha(name.encode()),), upstreams or self.UPSTREAMS, "BSD")
                for name in names]

    def complete(self, entries, current=(), listed=None):
        asked = []

        def list_jars(policy, component):
            asked.append(component)
            return listed

        added = mirror.completed_versions(mirror.Policy.load(), entries, list(current), jobs=1, list_jars=list_jars)
        return added, asked

    def test_the_jars_nobody_recorded_are_added_at_the_bytes_listed(self):
        recorded = self.entries("lwjgl-3.3.2.pom", "lwjgl-3.3.2.jar", "lwjgl-3.3.2-natives-linux.jar")
        added, asked = self.complete(recorded, listed={"lwjgl-3.3.2-natives-linux.jar": b"linux",
                                                       "lwjgl-3.3.2-natives-windows.jar": b"windows"})
        self.assertEqual(asked, [self.BASE])
        self.assertEqual([(e.path, e.hashes, e.upstreams, e.license) for e in added],
                         [(f"{self.BASE}/lwjgl-3.3.2-natives-windows.jar", (sha(b"windows"),), self.UPSTREAMS, "BSD")])

    def test_a_version_the_list_already_holds_whole_is_not_asked_about_again(self):
        recorded = self.entries("lwjgl-3.3.2.pom", "lwjgl-3.3.2.jar")
        extra = mirror.Entry(f"{self.BASE}/lwjgl-3.3.2-natives-windows.jar", ("a" * 64,), self.UPSTREAMS, "BSD")
        added, asked = self.complete(recorded, current=[*recorded, extra], listed={})
        self.assertEqual((added, asked), ([extra], []))
        # A file the mods record anew, or with other bytes, makes the version be asked about again
        more = recorded + self.entries("lwjgl-3.3.2-natives-linux.jar")
        _, asked = self.complete(more, current=[*recorded, extra], listed={})
        self.assertEqual(asked, [self.BASE])

    def test_versions_with_a_module_file_without_jars_or_under_an_explicit_rule_are_left_alone(self):
        for recorded in (self.entries("lwjgl-3.3.2.pom", "lwjgl-3.3.2.module", "lwjgl-3.3.2.jar"),
                         self.entries("lwjgl-3.3.2.pom"),
                         self.entries("lwjgl-3.3.2.pom", "lwjgl-3.3.2.jar", upstreams=("fabric",))):
            self.assertEqual(self.complete(recorded, listed={"lwjgl-3.3.2-x.jar": b"x"}), ([], []))

    def test_the_listing_is_read_from_the_upstream_and_checked_against_its_sha1(self):
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work) / self.BASE
            directory.mkdir(parents=True)
            files = {"lwjgl-3.3.2.pom": b"pom", "lwjgl-3.3.2.jar": b"jar", "lwjgl-3.3.2-natives-windows.jar": b"windows",
                     "lwjgl-3.3.2-javadoc.jar": b"docs", "lwjgl-3.3.2-sources.jar": b"sources",
                     "lwjgl-3.3.2-natives-windows.jar.asc": b"signature", "lwjgl-3.3.20-other.jar": b"other version"}
            for name, data in files.items():
                (directory / name).write_bytes(data)
            (directory / "lwjgl-3.3.2-natives-windows.jar.sha1").write_text(hashlib.sha1(b"windows").hexdigest())
            with serve(Path(work)) as url:
                policy = mirror.Policy.load()
                policy.upstreams = {**policy.upstreams, **{key: url for key in policy.by_pom.upstreams}}
                self.assertEqual(mirror.listed_jars(policy, self.BASE), {"lwjgl-3.3.2-natives-windows.jar": b"windows"})
                self.assertIsNone(mirror.listed_jars(policy, "org/lwjgl/lwjgl/9.9.9"))
                (directory / "lwjgl-3.3.2-natives-windows.jar.sha1").write_text("0" * 40)
                with self.assertRaises(mirror.MirrorError):
                    mirror.listed_jars(policy, self.BASE)


class PublisherStub(http.server.BaseHTTPRequestHandler):
    """Stands in for the publisher and the bucket: PUT stores under /v1/files/, GET reads the bucket."""
    files: dict = {}
    puts: list = []
    raw: list = []
    tokens: list = []
    fail_once: set = set()

    def log_message(self, *args):
        pass

    def do_PUT(self):
        length = int(self.headers["Content-Length"])
        data = self.rfile.read(length)
        self.raw.append(self.path)
        path = urllib.parse.unquote(self.path.removeprefix("/v1/files/"))
        self.tokens.append(self.headers["Authorization"])
        if path in self.fail_once:
            self.fail_once.discard(path)
            self.send_response(503)
            self.end_headers()
            return
        if self.headers["X-Sha256"] != sha(data):
            self.send_response(422)
            self.end_headers()
            return
        status = "present" if self.files.get(path) == data else "stored"
        self.files[path] = data
        self.puts.append(path)
        body = json.dumps({"status": status}).encode()
        self.send_response(200 if status == "present" else 201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        data = self.files.get(urllib.parse.unquote(self.path.lstrip("/")))
        self.send_response(200 if data is not None else 404)
        self.send_header("Content-Length", str(len(data or b"")))
        self.end_headers()
        self.wfile.write(data or b"")


class PublishTest(unittest.TestCase):
    JAR = "net/fabricmc/fabric-loader/1.0+b.1/fabric-loader-1.0+b.1.jar"

    def setUp(self):
        PublisherStub.files, PublisherStub.puts, PublisherStub.tokens, PublisherStub.fail_once = {}, [], [], set()
        PublisherStub.raw = []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PublisherStub)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        self.work = tempfile.TemporaryDirectory()
        self.site = Path(self.work.name)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.work.cleanup()

    def build(self, files):
        policy = mirror.Policy.load()
        store = self.site.parent / (self.site.name + "-store")
        entries = []
        for path, data in files.items():
            (store / path).parent.mkdir(parents=True, exist_ok=True)
            (store / path).write_bytes(data)
            entries.append(mirror.Entry(path, (sha(data),), ("fabric",), "Apache-2.0"))
        mirror.build_site(self.site, store, entries, {e.component for e in entries}, policy)

    def publish(self, **options):
        calls = []

        def token(fresh=False):
            calls.append(fresh)
            return "job-token"
        done = mirror.publish_site(self.site, self.url, self.url, token, jobs=2, **options)
        return done, calls

    def test_new_files_go_first_and_the_manifest_last(self):
        self.build({self.JAR: b"jar"})
        done, _ = self.publish()
        puts = PublisherStub.puts
        self.assertEqual(done["new"], 1)
        self.assertEqual(puts[0], self.JAR)
        self.assertEqual(puts[4], self.JAR + ".sha256")
        # A plus sign is sent encoded, so nothing between here and the bucket reads it as a space
        self.assertEqual(PublisherStub.raw[0], "/v1/files/net/fabricmc/fabric-loader/1.0%2Bb.1/fabric-loader-1.0%2Bb.1.jar")
        self.assertEqual(puts[-2:], ["index.html", "mirror-manifest.json"])
        self.assertIn("net/fabricmc/fabric-loader/maven-metadata.xml", puts)
        self.assertEqual(set(PublisherStub.tokens), {"Bearer job-token"})

    def test_no_pom_or_module_goes_before_the_jars(self):
        base = "net/fabricmc/fabric-loader/1.0"
        other = "net/fabricmc/other/2.0"
        self.build({f"{base}/fabric-loader-1.0.pom": b"pom", f"{base}/fabric-loader-1.0.module": b"module",
                    f"{base}/fabric-loader-1.0.jar": b"jar", f"{base}/fabric-loader-1.0-sources.jar": b"sources",
                    f"{other}/other-2.0.pom": b"pom 2", f"{other}/other-2.0.jar": b"jar 2"})
        self.publish()
        artifacts = [path for path in PublisherStub.puts
                     if path.endswith((".pom", ".module", ".jar")) and "maven-metadata" not in path]
        self.assertEqual(len(artifacts), 6)
        first_metadata = min(index for index, path in enumerate(artifacts) if path.endswith((".pom", ".module")))
        self.assertTrue(all(path.endswith(".jar") for path in artifacts[:first_metadata]))
        self.assertEqual(sum(path.endswith(".jar") for path in artifacts[:first_metadata]), 3)
        # Each jar's own checksum files are there as well before any metadata goes
        position = PublisherStub.puts.index(artifacts[first_metadata])
        self.assertEqual(sum(path.endswith(".jar.sha256") for path in PublisherStub.puts[:position]), 3)

    def test_what_the_manifest_already_lists_is_not_sent_again(self):
        self.build({self.JAR: b"jar"})
        self.publish()
        PublisherStub.puts.clear()
        other = "net/fabricmc/fabric-loader/2.0/fabric-loader-2.0.jar"
        self.build({self.JAR: b"jar", other: b"new"})
        done, _ = self.publish()
        self.assertEqual((done["files"], done["new"]), (2, 1))
        self.assertNotIn(self.JAR, PublisherStub.puts)
        self.assertIn(other, PublisherStub.puts)

    def test_a_run_cut_short_is_picked_up_from_the_checksum_marker(self):
        self.build({self.JAR: b"jar"})
        # The file and its .sha256 are in the bucket, but no manifest names them
        PublisherStub.files = {self.JAR: b"jar", self.JAR + ".sha256": sha(b"jar").encode()}
        done, _ = self.publish()
        self.assertEqual((done["new"], done["present"] >= 1), (1, True))
        self.assertNotIn(self.JAR, PublisherStub.puts)
        self.assertEqual(PublisherStub.puts[-1], "mirror-manifest.json")

    def test_a_refusal_from_the_host_is_tried_again_with_a_fresh_token(self):
        self.build({self.JAR: b"jar"})
        PublisherStub.fail_once = {"index.html"}
        original, mirror.time.sleep = mirror.time.sleep, lambda seconds: None
        try:
            _, calls = self.publish()
        finally:
            mirror.time.sleep = original
        self.assertIn(True, calls)
        self.assertEqual(PublisherStub.puts[-2:], ["index.html", "mirror-manifest.json"])

    def test_a_job_without_a_token_cannot_publish(self):
        with self.assertRaises(mirror.MirrorError):
            mirror.JobToken("https://maven.example").request()


class FillTest(unittest.TestCase):
    def run_fill(self, upstream_files, lock_lines, **extra):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            upstream = work / "upstream"
            for path, data in upstream_files.items():
                (upstream / path).parent.mkdir(parents=True, exist_ok=True)
                (upstream / path).write_bytes(data)
            lock = work / "artifacts.lock"
            lock.write_text("\n".join(lock_lines) + "\n")
            policy_data = json.loads(mirror.POLICY.read_text())
            with serve(upstream) as url:
                policy_data["upstreams"] = {key: url for key in policy_data["upstreams"]}
                policy_file = work / "policy.json"
                policy_file.write_text(json.dumps(policy_data))
                original = (mirror.LOCK, mirror.POLICY)
                mirror.LOCK, mirror.POLICY = lock, policy_file
                try:
                    args = SimpleNamespace(site=str(work / "site"), store=str(work / "store"), seed_gradle=[],
                                           seed_maven=[], pages=None, no_upstream=False, jobs=2,
                                           allow_incomplete=extra.get("allow_incomplete", False),
                                           allow_regression=False, summary=None, github_output=None)
                    status = mirror.cmd_fill(args)
                finally:
                    mirror.LOCK, mirror.POLICY = original
            site = work / "site"
            files = sorted(str(p.relative_to(site)).replace("\\", "/") for p in site.rglob("*") if p.is_file()) \
                if site.exists() else []
            return status, files

    def test_upstream_mismatch_refuses_to_publish(self):
        path = "net/fabricmc/fabric-loader/1.0/fabric-loader-1.0.jar"
        status, files = self.run_fill({path: b"tampered"}, [f"{sha(b'good')} fabric Apache-2.0 {path}"])
        self.assertEqual(status, 1)
        self.assertEqual(files, [])

    def test_matching_file_is_published_with_checksums_and_metadata(self):
        path = "net/fabricmc/fabric-loader/1.0/fabric-loader-1.0.jar"
        status, files = self.run_fill({path: b"good"}, [f"{sha(b'good')} fabric Apache-2.0 {path}"])
        self.assertEqual(status, 0)
        for suffix in ("", ".md5", ".sha1", ".sha256", ".sha512"):
            self.assertIn(path + suffix, files)
        self.assertIn("net/fabricmc/fabric-loader/maven-metadata.xml", files)

    def test_incomplete_component_is_withheld(self):
        jar = "net/fabricmc/fabric-loader/1.0/fabric-loader-1.0.jar"
        pom = "net/fabricmc/fabric-loader/1.0/fabric-loader-1.0.pom"
        status, files = self.run_fill({jar: b"good"}, [f"{sha(b'good')} fabric Apache-2.0 {jar}",
                                                       f"{sha(b'pom')} fabric Apache-2.0 {pom}"],
                                      allow_incomplete=True)
        self.assertEqual(status, 0)
        self.assertNotIn(jar, files)


class SizeAlertTest(unittest.TestCase):
    def test_below_ninety_percent_passes(self):
        self.assertIsNone(mirror.size_alert(mirror.SITE_ALERT))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mirror.main(["check-size", "--bytes", str(834_000_000)]), 0)

    def test_above_ninety_percent_fails_with_a_clear_message(self):
        over = mirror.SITE_ALERT + 1
        self.assertIn("alert above 90%", mirror.size_alert(over))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(mirror.main(["check-size", "--bytes", str(over), "--annotate"]), 1)
        self.assertTrue(out.getvalue().startswith("::error title=Mirror size::the site is "))


if __name__ == "__main__":
    unittest.main()

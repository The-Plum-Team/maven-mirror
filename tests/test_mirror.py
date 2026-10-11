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

    def test_central_artifacts_are_not_covered(self):
        self.assertEqual(self.policy.classify("com.google.guava", "guava")[0], "uncovered")

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
        self.assertIsNone(mirror.size_alert(mirror.PAGES_SITE_ALERT))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mirror.main(["check-size", "--bytes", str(834_000_000)]), 0)

    def test_above_ninety_percent_fails_with_a_clear_message(self):
        over = mirror.PAGES_SITE_ALERT + 1
        self.assertIn("alert above 90%", mirror.size_alert(over))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(mirror.main(["check-size", "--bytes", str(over), "--annotate"]), 1)
        self.assertTrue(out.getvalue().startswith("::error title=Mirror size::the site is "))


if __name__ == "__main__":
    unittest.main()

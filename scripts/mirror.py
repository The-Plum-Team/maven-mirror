#!/usr/bin/env python3
"""Hash-checked static Maven mirror for The Plum Team's mod builds.

Subcommands:
  update-list    regenerate artifacts.lock and excluded.txt from the mods' Gradle
                 dependency-verification metadata, filtered by policy.json
  fill           obtain every locked file (verified store, seeds, the published
                 mirror, then the upstream), verify its sha256, and build the site
  publish        send what the site holds and the mirror lacks to the mirror's publisher
  verify-remote  download files from a published mirror and check them against the lock
  check-size     fail when a site size is above 90% of the bucket's free allowance

Only the Python standard library is used. Every file that enters the store or the site has
matched a sha256 from artifacts.lock; a mismatch from an upstream is fatal.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy.json"
SOURCES = ROOT / "sources.json"
LOCK = ROOT / "artifacts.lock"
EXCLUDED = ROOT / "excluded.txt"
VERIFICATION_NS = "{https://schema.gradle.org/dependency-verification}"
USER_AGENT = "The-Plum-Team-maven-mirror/1 (+https://github.com/The-Plum-Team/maven-mirror)"
# The publisher (worker/) takes a file in one request, and a Worker accepts at most this much.
FILE_LIMIT = 100 * 1024 * 1024
# What Cloudflare R2 stores without charge. Nothing stops at it: above it the bucket is billed.
SITE_LIMIT = 10 * 1024 * 1024 * 1024
SITE_WARN = int(SITE_LIMIT * 0.8)
SITE_ALERT = int(SITE_LIMIT * 0.9)
POM_LIMIT = 1024 * 1024
POM_PARENTS = 8
SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CHECKSUMS = ("md5", "sha1", "sha256", "sha512")
HOST_FAILURE_LIMIT = 6  # consecutive network errors before a host is skipped for the rest of a run
MANIFEST = "mirror-manifest.json"
DISPUTED = "disputed"
# The files that tell Gradle a version is in a repository
METADATA_SUFFIXES = (".pom", ".module")
DEFAULT_MIRROR = "https://maven.quickskin.net/"
# Where the mirror was published until it moved; it stays as it was then, and is still read
# before any upstream for the files it holds.
LEGACY_PAGES = "https://the-plum-team.github.io/maven-mirror/"
DEFAULT_PUBLISHER = "https://maven-upload.quickskin.net/"


class MirrorError(Exception):
    pass


# --------------------------------------------------------------------------- policy


@dataclass(frozen=True)
class Rule:
    group: re.Pattern
    module: re.Pattern
    license: str = ""
    upstreams: tuple = ()
    reason: str = ""


@dataclass(frozen=True)
class PomRule:
    """Components that no rule names: mirrored by the license their own POM declares."""
    upstreams: tuple
    licenses: tuple  # (label, (compiled patterns, ...))
    skip_files: tuple = ()  # compiled patterns of listed files that are never added

    def recognise(self, declared) -> list[str]:
        """The labels of the declared (name, url) licenses this rule accepts."""
        found = []
        for name, url in declared:
            text = f"{name} {url}".lower()
            for label, patterns in self.licenses:
                if label not in found and any(p.search(text) for p in patterns):
                    found.append(label)
        return sorted(found)


@dataclass
class Policy:
    upstreams: dict
    include: list
    exclude: list
    by_pom: PomRule | None = None

    @classmethod
    def load(cls, path: Path | None = None) -> "Policy":
        data = json.loads((path or POLICY).read_text(encoding="utf-8"))
        upstreams = data["upstreams"]
        for key, url in upstreams.items():
            secure = url.startswith("https://") or url.startswith("http://127.0.0.1:")  # tests only
            if not secure or not url.endswith("/"):
                raise MirrorError(f"upstream {key} must be an https URL ending in '/': {url}")
        include = []
        for raw in data["include"]:
            ups = tuple(raw["upstreams"])
            unknown = [u for u in ups if u not in upstreams]
            if unknown or not ups or not raw.get("license") or not raw.get("evidence"):
                raise MirrorError(f"include rule needs known upstreams, license and evidence: {raw}")
            include.append(Rule(re.compile(raw["group"]), re.compile(raw["module"]),
                                raw["license"], ups))
        exclude = [Rule(re.compile(r["group"]), re.compile(r["module"]), reason=r["reason"])
                   for r in data["exclude"]]
        by_pom = None
        if "by_pom" in data:
            raw = data["by_pom"]
            ups = tuple(raw["upstreams"])
            if not ups or any(u not in upstreams for u in ups) or not raw.get("licenses"):
                raise MirrorError("by_pom needs known upstreams and at least one license")
            for label in raw["licenses"]:
                if not SEGMENT.fullmatch(label):
                    raise MirrorError(f"by_pom license label is not a plain word: {label!r}")
            by_pom = PomRule(ups, tuple((label, tuple(re.compile(p) for p in patterns))
                                        for label, patterns in raw["licenses"].items()),
                             tuple(re.compile(p) for p in raw.get("skip_files", [])))
        return cls(upstreams, include, exclude, by_pom)

    def classify(self, group: str, module: str):
        """Return ("exclude", reason), ("include", rule) or ("uncovered", None)."""
        for rule in self.exclude:
            if rule.group.fullmatch(group) and rule.module.fullmatch(module):
                return "exclude", rule.reason
        for rule in self.include:
            if rule.group.fullmatch(group) and rule.module.fullmatch(module):
                return "include", rule
        return "uncovered", None

    def mirrored_group(self, group: str) -> bool:
        return any(rule.group.fullmatch(group) for rule in self.include)


# --------------------------------------------------------------------------- lock


@dataclass(frozen=True)
class Entry:
    path: str
    hashes: tuple
    upstreams: tuple
    license: str
    # The mods record different sets of sha256 for this file, and `hashes` holds only the ones they
    # all trust. An upstream may by now serve bytes that only some of them trust, which is no sign
    # of tampering: such a file is left out until they agree, instead of stopping the run.
    disputed: bool = False

    @property
    def component(self) -> str:
        return self.path.rsplit("/", 1)[0]

    def line(self) -> str:
        line = f"{','.join(self.hashes)} {','.join(self.upstreams)} {self.license} {self.path}"
        return f"{line} {DISPUTED}" if self.disputed else line


def check_path(path: str) -> str:
    parts = path.split("/")
    if len(parts) < 4 or not all(SEGMENT.fullmatch(p) for p in parts):
        raise MirrorError(f"unsafe or malformed repository path: {path!r}")
    return path


def read_lock(path: Path | None = None) -> list[Entry]:
    path = path or LOCK
    entries = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) not in (4, 5) or fields[4:] not in ([], [DISPUTED]):
            raise MirrorError(f"{path.name}:{number}: expected 4 fields, or 5 ending in '{DISPUTED}'")
        hashes = tuple(fields[0].split(","))
        if not all(HEX64.fullmatch(h) for h in hashes):
            raise MirrorError(f"{path.name}:{number}: malformed sha256")
        entries.append(Entry(check_path(fields[3]), hashes, tuple(fields[1].split(",")), fields[2],
                             len(fields) == 5))
    paths = [e.path for e in entries]
    if len(paths) != len(set(paths)):
        raise MirrorError(f"{path.name}: duplicate paths")
    return entries


# --------------------------------------------------------------------------- update-list


def http_get(url: str, timeout: float = 60, headers: dict | None = None) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def get_or_none(url: str, attempts: int = 4, timeout: float = 30) -> bytes | None:
    """The body at url, or None when its host says it is not there (404 or 410).

    Anything else that goes wrong is tried again and then stops the run, so that a host that
    cannot be read is never taken for one that lacks the file.
    """
    last = "error"
    for attempt in range(attempts):
        try:
            return http_get(url, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                return None
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
        time.sleep(2 * (attempt + 1))
    raise MirrorError(f"could not read {url}: {last}")


def mirror_bases(values) -> list[str]:
    """The published mirrors to read before any upstream, as URLs ending in '/'."""
    if values is None:
        return [DEFAULT_MIRROR, LEGACY_PAGES]
    if isinstance(values, str):
        values = [values]
    return [value.rstrip("/") + "/" for value in values if value]


def resolve_source(source: dict) -> tuple[str, bytes]:
    repository, ref, path = source["repository"], source["ref"], source["path"]
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    commit = json.loads(http_get(f"https://api.github.com/repos/{repository}/commits/{ref}",
                                 headers=headers))["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise MirrorError(f"unexpected commit id for {repository}@{ref}")
    data = http_get(f"https://raw.githubusercontent.com/{repository}/{commit}/{path}")
    return f"{repository}@{commit}:{path}", data


def parse_verification(data: bytes):
    root = ET.fromstring(data)
    for component in root.iter(f"{VERIFICATION_NS}component"):
        group, name, version = (component.get(k) for k in ("group", "name", "version"))
        for artifact in component.findall(f"{VERIFICATION_NS}artifact"):
            hashes = []
            for sha in artifact.findall(f"{VERIFICATION_NS}sha256"):
                hashes.append(sha.get("value"))
                hashes.extend(a.get("value") for a in sha.findall(f"{VERIFICATION_NS}also-trust"))
            yield group, name, version, artifact.get("name"), tuple(hashes)


# --------------------------------------------------------------------------- licenses by POM


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def read_pom(data: bytes):
    """Return what a POM declares: its licenses as [(name, url), ...] and its parent as
    (group, name, version), or None when it has none or names it through a property."""
    if len(data) > POM_LIMIT or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise MirrorError("POM is too large or declares a document type")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise MirrorError(f"POM is not well-formed: {exc}") from exc
    licenses, parent = [], None
    for child in root:
        tag = _local(child.tag)
        if tag == "licenses":
            for item in child:
                fields = {_local(x.tag): (x.text or "").strip() for x in item}
                if fields.get("name") or fields.get("url"):
                    licenses.append((fields.get("name", ""), fields.get("url", "")))
        elif tag == "parent":
            fields = {_local(x.tag): (x.text or "").strip() for x in child}
            gav = (fields.get("groupId", ""), fields.get("artifactId", ""), fields.get("version", ""))
            if all(gav) and not any("${" in part for part in gav):
                parent = gav
    return licenses, parent


def recorded_files(documents) -> dict:
    """Every file the mods record, by component: {(group, name, version): {filename: {sha256, ...}}}."""
    recorded: dict = {}
    for _, data in documents:
        for group, name, version, filename, hashes in parse_verification(data):
            recorded.setdefault((group, name, version), {}).setdefault(filename, set()).update(
                h for h in hashes if h)
    return recorded


class Poms:
    """Reads POMs to learn which license a component declares.

    A POM comes from a published mirror or from the upstreams of `by_pom`, in that order. When the
    mods record that POM, only bytes with a recorded sha256 are believed. A POM nobody recorded is
    read as its upstream serves it: it decides only whether the files that are recorded get
    mirrored. Only "not found" means a POM is absent; a host that cannot be read stops the run, so
    an outage never looks like a missing license.
    """

    def __init__(self, policy: Policy, recorded: dict, mirrors: list[str], jobs: int = 16):
        self.rule = policy.by_pom
        self.recorded = recorded
        self.bases = list(mirrors) + [policy.upstreams[u] for u in self.rule.upstreams]
        self.jobs = jobs
        self.cache: dict = {}
        self.guard = threading.Lock()

    def fetch(self, gav) -> bytes | None:
        with self.guard:
            if gav in self.cache:
                return self.cache[gav]
        data = self._read(gav)
        with self.guard:
            self.cache[gav] = data
        return data

    def _read(self, gav) -> bytes | None:
        group, name, version = gav
        filename = f"{name}-{version}.pom"
        try:
            path = check_path("/".join([*group.split("."), name, version, filename]))
        except MirrorError:
            return None
        expected = self.recorded.get(gav, {}).get(filename)
        mismatched = []
        for base in self.bases:
            data = get_or_none(base + path)
            if data is None:
                continue
            if expected and hashlib.sha256(data).hexdigest() not in expected:
                mismatched.append(base)
                continue
            return data
        if mismatched:
            raise MirrorError(f"{path} from {', '.join(mismatched)} does not have a sha256 the mods record")
        return None

    def prefetch(self, gavs) -> None:
        """Read the POMs of these components and of their parents, several at a time."""
        pending = set(gavs)
        for _ in range(POM_PARENTS + 1):
            with self.guard:
                pending = {gav for gav in pending if gav not in self.cache}
            if not pending:
                return
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.jobs) as pool:
                results = list(pool.map(self.fetch, sorted(pending)))
            pending = set()
            for data in results:
                if data is None:
                    continue
                try:
                    licenses, parent = read_pom(data)
                except MirrorError:
                    continue
                if parent is not None and not licenses:
                    pending.add(parent)

    def decide(self, gav) -> tuple[str, str]:
        """Return (license label, "") when the component may be mirrored, else ("", the reason)."""
        own = self.fetch(gav)
        if own is None:
            return "", "no POM on Maven Central or the Gradle Plugin Portal"
        reason = f"no license within {POM_PARENTS} parent POMs"
        current, data = gav, own
        for _ in range(POM_PARENTS + 1):
            try:
                licenses, parent = read_pom(data)
            except MirrorError as exc:
                reason = f"{':'.join(current)}: {exc}"
                break
            if licenses:
                labels = self.rule.recognise(licenses)
                if labels:
                    return "/".join(labels), ""
                declared = "; ".join(name or url for name, url in licenses)
                return "", f"no declared license is one the policy recognises: {declared}"
            if parent is None:
                reason = "no license in its POM or its parents"
                break
            current, data = parent, self.fetch(parent)
            if data is None:
                reason = f"its parent POM {':'.join(parent)} was not found"
                break
        files = self.recorded.get(gav, {})
        if files and all(name.endswith(".pom") for name in files):
            # Build metadata only, such as a parent POM: nothing but the POM itself is redistributed
            return "metadata-only", ""
        return "", reason


def build_list(policy: Policy, documents: list[tuple[str, bytes]], poms: Poms | None = None):
    entries: dict[str, Entry] = {}
    excluded: dict[str, str] = {}
    uncovered: set[str] = set()
    conflicts: set[str] = set()
    decided: dict = {}
    if poms is not None:
        candidates = sorted({(group, name, version)
                             for _, data in documents
                             for group, name, version, _, _ in parse_verification(data)
                             if policy.classify(group, name)[0] == "uncovered"})
        poms.prefetch(candidates)
        decided = {gav: poms.decide(gav) for gav in candidates}
    for label, data in documents:
        for group, name, version, filename, hashes in parse_verification(data):
            gav = f"{group}:{name}:{version}"
            verdict, detail = policy.classify(group, name)
            if verdict == "exclude":
                excluded[gav] = detail
                continue
            if verdict == "uncovered":
                decision = decided.get((group, name, version))
                if decision is None:
                    if policy.mirrored_group(group):
                        uncovered.add(gav)
                    continue
                if not decision[0]:
                    excluded[gav] = decision[1]
                    continue
                detail = Rule(re.compile(""), re.compile(""), decision[0], policy.by_pom.upstreams)
            if not hashes or not all(h and HEX64.fullmatch(h) for h in hashes):
                raise MirrorError(f"{label}: {gav} {filename} has no usable sha256")
            if not filename.startswith(f"{name}-{version}"):
                # e.g. a parent POM recorded under its child's component: not at this path.
                excluded[f"{gav} {filename}"] = "artifact file does not belong to this component path"
                continue
            path = check_path("/".join([*group.split("."), name, version, filename]))
            entry = Entry(path, tuple(sorted(set(hashes))), detail.upstreams, detail.license)
            previous = entries.get(path)
            if previous and previous.hashes != entry.hashes:
                # The mods trust different sets of bytes for this file (a module an upstream
                # published again, which only some of them recorded, for one). The mirror may
                # serve only bytes every one of them trusts.
                shared = tuple(sorted(set(previous.hashes) & set(entry.hashes)))
                if not shared:
                    conflicts.add(entry.component)
                else:
                    entries[path] = Entry(path, shared, previous.upstreams, previous.license, True)
                continue
            entries.setdefault(path, entry)
    # Two mods recorded bytes for the same file that have nothing in common. Mirroring either one
    # would break the other mod's verification, so the whole component stays on its upstream until
    # they agree.
    for component in conflicts:
        group_path, name, version = component.rsplit("/", 2)
        excluded[f"{group_path.replace('/', '.')}:{name}:{version}"] = (
            "the verification sources record different sha256 values for this component")
    kept = [e for e in entries.values() if e.component not in conflicts]
    return sorted(kept, key=lambda e: e.path), excluded, uncovered


def fetch_verified(entry: Entry, policy: Policy, mirrors: list[str]) -> bytes:
    """Return the bytes of a locked file from a mirror or its upstreams, checked against the lock."""
    bases = list(mirrors) + [policy.upstreams[u] for u in entry.upstreams]
    problems = []
    for base in bases:
        try:
            data = http_get(base + entry.path, timeout=30)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            problems.append(f"{base}: {getattr(exc, 'reason', exc)}")
            continue
        if hashlib.sha256(data).hexdigest() in entry.hashes:
            return data
        problems.append(f"{base}: sha256 does not match the reviewed list")
    raise MirrorError(f"could not obtain {entry.path}: {'; '.join(problems)}")


def module_declared(entries: list[Entry], read_module) -> list[Entry]:
    """Files that a locked Gradle .module declares but no verification metadata records.

    Gradle takes every file of a version from the repository that served its metadata, so a file
    the mirror lacks (such as a sources jar) fails the build instead of falling back upstream. Each
    locked .module is fetched and checked against its locked sha256, and the sha256 it declares for
    each of its own files is trusted in turn. Javadoc jars are left out to save space.
    """
    known = {e.path for e in entries}
    added: dict[str, Entry] = {}
    for entry in entries:
        if not entry.path.endswith(".module"):
            continue
        document = json.loads(read_module(entry))
        directory = entry.component
        for variant in document.get("variants", []):
            if "available-at" in variant:
                continue
            for item in variant.get("files", []):
                url, digest = item.get("url", ""), item.get("sha256", "")
                if "/" in url or url.endswith("-javadoc.jar"):
                    continue
                path = check_path(f"{directory}/{url}")
                if path in known or path in added:
                    continue
                if not HEX64.fullmatch(digest):
                    raise MirrorError(f"{entry.path} declares {url} without a usable sha256")
                added[path] = Entry(path, (digest,), entry.upstreams, entry.license)
    return list(added.values())


HREF = re.compile(r'href="([^"?#/]+)"')


def listed_jars(policy: Policy, component: str) -> dict[str, bytes] | None:
    """The other jars an upstream lists for a version, with their bytes; None when none lists it.

    The file names come from the upstream's own index of the version's directory. Each file is
    read from that same upstream and, when the upstream publishes a .sha1 for it, checked against it.
    """
    name, version = component.rsplit("/", 2)[1:]
    prefix = f"{name}-{version}"
    rule = policy.by_pom
    for upstream in rule.upstreams:
        base = policy.upstreams[upstream]
        index = get_or_none(f"{base}{component}/")
        if index is None:
            continue
        names = sorted({n for n in HREF.findall(index.decode("utf-8", "replace"))
                        if n.startswith(prefix + "-") and n.endswith(".jar") and SEGMENT.fullmatch(n)
                        and not any(p.search(n) for p in rule.skip_files)})
        if not names and f'"{prefix}.pom"' not in index.decode("utf-8", "replace"):
            continue  # not an index of this version: a host that answers every path
        found = {}
        for filename in names:
            data = get_or_none(f"{base}{component}/{filename}")
            if data is None:
                continue
            sidecar = get_or_none(f"{base}{component}/{filename}.sha1")
            if sidecar is not None:
                stated = sidecar.decode("ascii", "replace").split()
                if not stated or stated[0].lower() != hashlib.sha1(data).hexdigest():
                    raise MirrorError(f"{component}/{filename} from {base} does not have the sha1 published beside it")
            found[filename] = data
        return found
    return None


def completed_versions(policy: Policy, entries: list[Entry], current: list[Entry], jobs: int = 6,
                       list_jars=listed_jars) -> list[Entry]:
    """The jars of `by_pom` versions that no mod records but a build on another machine may ask for.

    Gradle takes every file of a version from the repository that served its metadata. A version
    published with a .module is completed from what that .module declares (module_declared). One
    published with only a POM declares nothing, so the other jars its upstream lists are added, each
    pinned at the sha256 of the bytes served now. A version the current list already holds whole
    is not asked about again: what an upstream published under a version does not change.
    """
    rule = policy.by_pom
    if rule is None:
        return []
    by_component: dict[str, list[Entry]] = {}
    for entry in entries:
        if entry.upstreams == rule.upstreams:
            by_component.setdefault(entry.component, []).append(entry)
    held: dict[str, dict[str, Entry]] = {}
    for entry in current:
        held.setdefault(entry.component, {})[entry.path] = entry

    def complete(item) -> list[Entry]:
        component, recorded = item
        names = {e.path.rsplit("/", 1)[1] for e in recorded}
        if any(n.endswith(".module") for n in names) or not any(n.endswith(".jar") for n in names):
            return []
        before = held.get(component, {})
        if all(e.path in before and before[e.path].hashes == e.hashes for e in recorded):
            known = {e.path for e in recorded}
            return [e for path, e in sorted(before.items()) if path not in known]
        listed = list_jars(policy, component)
        if listed is None:
            return []
        first = recorded[0]
        return [Entry(check_path(f"{component}/{filename}"), (hashlib.sha256(data).hexdigest(),),
                      first.upstreams, first.license)
                for filename, data in sorted(listed.items()) if filename not in names]

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        return [entry for added in pool.map(complete, sorted(by_component.items())) for entry in added]


def render_lock(entries, labels) -> str:
    header = [
        "# Reviewed artifact list. Generated by `python3 scripts/mirror.py update-list`; do not edit by hand.",
        "# Format: <sha256>[,<also-trusted sha256>...] <upstream ids> <license> <path> [disputed]",
        "# disputed: the mods record different sha256 for the file; only the ones they all trust are listed.",
        *[f"# Source: {label}" for label in labels],
    ]
    return "\n".join(header + [e.line() for e in entries]) + "\n"


def render_excluded(excluded, uncovered) -> str:
    lines = ["# Components seen in the mods' verification metadata that are NOT mirrored.",
             "# Generated by `python3 scripts/mirror.py update-list`.", "",
             "## Excluded by policy.json"]
    lines += [f"{gav}  # {reason}" for gav, reason in sorted(excluded.items())]
    lines += ["", "## In a mirrored group but not covered by any include rule (review needed)"]
    lines += sorted(uncovered) or ["(none)"]
    return "\n".join(lines) + "\n"


def cmd_update_list(args) -> int:
    policy = Policy.load()
    if args.metadata:
        documents = [(f"local:{Path(p).name}", Path(p).read_bytes()) for p in args.metadata]
    else:
        sources = json.loads(SOURCES.read_text(encoding="utf-8"))["sources"]
        documents = [resolve_source(s) for s in sources]
    mirrors = mirror_bases(args.pages)
    poms = Poms(policy, recorded_files(documents), mirrors) if policy.by_pom else None
    entries, excluded, uncovered = build_list(policy, documents, poms)
    current = read_lock() if LOCK.exists() and not args.relist else []
    entries = sorted(entries + module_declared(entries, lambda e: fetch_verified(e, policy, mirrors))
                     + completed_versions(policy, entries, current), key=lambda e: e.path)
    lock_text = render_lock(entries, [label for label, _ in documents])
    excluded_text = render_excluded(excluded, uncovered)
    summary = (f"{len(entries)} files in {len({e.component for e in entries})} components; "
               f"{len(excluded)} excluded; {len(uncovered)} uncovered in mirrored groups")
    if args.check:
        current = [e.line() for e in read_lock()] if LOCK.exists() else []
        fresh = [e.line() for e in entries]
        added = sorted(set(fresh) - set(current))
        removed = sorted(set(current) - set(fresh))
        report = [f"Drift check against {', '.join(label for label, _ in documents)}", summary,
                  f"{len(added)} lines to add, {len(removed)} lines to remove"]
        report += [f"+ {line}" for line in added[:50]] + [f"- {line}" for line in removed[:50]]
        print("\n".join(report))
        if args.summary:
            with open(args.summary, "a", encoding="utf-8") as handle:
                handle.write("### Artifact list drift\n\n```\n" + "\n".join(report) + "\n```\n")
        return 0
    LOCK.write_text(lock_text, encoding="utf-8", newline="\n")
    EXCLUDED.write_text(excluded_text, encoding="utf-8", newline="\n")
    print(summary)
    return 0


# --------------------------------------------------------------------------- fill


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: Path, attempts: int = 3, timeout: float = 30) -> str:
    """Return "ok", "missing" (404/410) or an error description."""
    last = "error"
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response, dest.open("wb") as out:
                shutil.copyfileobj(response, out, 1 << 20)
            return "ok"
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                return "missing"
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
        time.sleep(2 * (attempt + 1))
    return last


@dataclass
class Outcome:
    entry: Entry
    source: str = ""
    notes: list = field(default_factory=list)
    fatal: str = ""


class Filler:
    def __init__(self, args, policy: Policy):
        self.policy = policy
        self.store = Path(args.store).resolve()
        self.seed_gradle = [Path(p) for p in args.seed_gradle]
        self.seed_maven = [Path(p) for p in args.seed_maven]
        self.mirrors = mirror_bases(args.pages or [])
        self.upstream = not args.no_upstream
        self.failures: dict[str, int] = {}
        self.lock = threading.Lock()

    def host_down(self, kind: str) -> bool:
        with self.lock:
            return self.failures.get(kind, 0) >= HOST_FAILURE_LIMIT

    def record(self, kind: str, reachable: bool) -> None:
        with self.lock:
            if reachable:
                self.failures[kind] = 0
            else:
                self.failures[kind] = self.failures.get(kind, 0) + 1
                if self.failures[kind] == HOST_FAILURE_LIMIT:
                    print(f"{kind} failed {HOST_FAILURE_LIMIT} times in a row; skipping it for this run",
                          flush=True)

    def unreachable_hosts(self) -> list[str]:
        return sorted(k for k, v in self.failures.items() if v >= HOST_FAILURE_LIMIT)

    def candidates(self, entry: Entry):
        group_path, name, version, filename = entry.path.rsplit("/", 3)
        group = group_path.replace("/", ".")
        for seed in self.seed_maven:
            yield "seed", seed / entry.path
        for seed in self.seed_gradle:
            directory = seed / group / name / version
            if directory.is_dir():
                for hashed in sorted(directory.iterdir()):
                    yield "seed", hashed / filename
        for number, base in enumerate(self.mirrors, 1):
            yield ("mirror" if number == 1 else f"mirror:{number}"), base + entry.path
        if self.upstream:
            for upstream in entry.upstreams:
                yield f"upstream:{upstream}", self.policy.upstreams[upstream] + entry.path

    def obtain(self, entry: Entry) -> Outcome:
        outcome = Outcome(entry)
        target = self.store / entry.path
        if target.is_file():
            if sha256_file(target) in entry.hashes:
                outcome.source = "store"
                return outcome
            outcome.notes.append("store copy has a different sha256; discarded")
            target.unlink()
        target.parent.mkdir(parents=True, exist_ok=True)
        for kind, location in self.candidates(entry):
            handle, temp_name = tempfile.mkstemp(dir=target.parent, prefix=".part-")
            os.close(handle)
            temp = Path(temp_name)
            try:
                if isinstance(location, Path):
                    if not location.is_file():
                        continue
                    shutil.copyfile(location, temp)
                    status = "ok"
                else:
                    if self.host_down(kind):
                        outcome.notes.append(f"{kind}: skipped, host unreachable")
                        continue
                    status = download(location, temp)
                    self.record(kind, status in ("ok", "missing"))
                if status == "missing":
                    continue
                if status != "ok":
                    outcome.notes.append(f"{kind}: {status}")
                    continue
                actual = sha256_file(temp)
                if actual not in entry.hashes:
                    message = f"{kind}: sha256 {actual} does not match the reviewed list"
                    if kind.startswith("upstream") and not entry.disputed:
                        outcome.fatal = message
                        return outcome
                    if entry.disputed:
                        message += " (the mods disagree about this file; it is left out until they agree)"
                    outcome.notes.append(message)
                    continue
                os.replace(temp, target)
                outcome.source = kind
                return outcome
            finally:
                temp.unlink(missing_ok=True)
        return outcome


def version_key(version: str):
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.+-]", version)]


def maven_metadata(group: str, name: str, versions: list[str]) -> bytes:
    ordered = sorted(versions, key=version_key)
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<metadata>",
             f"  <groupId>{group}</groupId>", f"  <artifactId>{name}</artifactId>",
             "  <versioning>", f"    <latest>{ordered[-1]}</latest>",
             f"    <release>{ordered[-1]}</release>", "    <versions>"]
    lines += [f"      <version>{v}</version>" for v in ordered]
    lines += ["    </versions>", "  </versioning>", "</metadata>", ""]
    return "\n".join(lines).encode("utf-8")


def write_checksums(path: Path, data: bytes | None = None) -> None:
    if data is None:
        data = path.read_bytes()
    for algorithm in CHECKSUMS:
        Path(f"{path}.{algorithm}").write_text(hashlib.new(algorithm, data).hexdigest(),
                                                encoding="ascii")


def link_or_copy(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, dest)
    except OSError:
        shutil.copyfile(source, dest)


def build_site(site: Path, store: Path, entries: list[Entry], complete: set[str],
               policy: Policy) -> dict:
    if site.exists():
        shutil.rmtree(site)
    site.mkdir(parents=True)
    modules: dict[tuple[str, str], list[str]] = {}
    manifest = []
    total = 0
    for entry in entries:
        if entry.component not in complete:
            continue
        source = store / entry.path
        size = source.stat().st_size
        if size > FILE_LIMIT:
            raise MirrorError(f"{entry.path} is {size} bytes, more than the publisher takes in one file")
        dest = site / entry.path
        link_or_copy(source, dest)
        write_checksums(dest)
        total += size
        group_path, name, version, _ = entry.path.rsplit("/", 3)
        versions = modules.setdefault((group_path, name), [])
        if version not in versions:
            versions.append(version)
        manifest.append({"path": entry.path, "sha256": sha256_file(dest), "size": size,
                         "license": entry.license,
                         "upstream": [policy.upstreams[u] for u in entry.upstreams]})
    for (group_path, name), versions in sorted(modules.items()):
        data = maven_metadata(group_path.replace("/", "."), name, versions)
        path = site / group_path / name / "maven-metadata.xml"
        path.write_bytes(data)
        write_checksums(path, data)
    site_bytes = sum(p.stat().st_size for p in site.rglob("*") if p.is_file())
    (site / MANIFEST).write_text(json.dumps({"files": manifest}, indent=1) + "\n", encoding="utf-8")
    (site / "index.html").write_text(INDEX_HTML.format(
        files=len(manifest), components=len(complete), modules=len(modules),
        megabytes=f"{site_bytes / 1e6:.1f}"), encoding="utf-8")
    site_bytes = sum(p.stat().st_size for p in site.rglob("*") if p.is_file())
    return {"artifact_bytes": total, "site_bytes": site_bytes, "files": len(manifest),
            "components": len(complete), "modules": len(modules)}


INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Plum Maven Mirror</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#222;background:#fff}}
code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px}}@media (prefers-color-scheme:dark){{body{{color:#ddd;background:#161616}}code{{background:#2a2a2a}}}}</style>
</head><body>
<h1>Plum Maven Mirror</h1>
<p>A hash-checked mirror of the openly licensed build dependencies used by The Plum Team's mods:
Fabric, Architectury, Stonecutter, NeoForge, Forge and GeckoLib artifacts, and the libraries and
Gradle plugins those builds take from Maven Central and the Gradle Plugin Portal. It holds no
Minecraft or Mojang files.</p>
<p>{files} files, {components} versions of {modules} modules, {megabytes} MB in total.
Every file matched a reviewed sha256 before it was published; the list is in
<a href="mirror-manifest.json"><code>mirror-manifest.json</code></a>.</p>
<p>Source, policy and licenses: <a href="https://github.com/The-Plum-Team/maven-mirror">github.com/The-Plum-Team/maven-mirror</a>.</p>
</body></html>
"""


def published_files(base: str | None) -> dict[str, str]:
    """What a published mirror's manifest lists: {path: sha256}; nothing when it has no manifest yet."""
    if not base:
        return {}
    try:
        data = json.loads(http_get(base.rstrip("/") + "/" + MANIFEST))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        raise MirrorError(f"could not read the published manifest: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise MirrorError(f"could not read the published manifest: {exc}") from exc
    return {item["path"]: item["sha256"] for item in data["files"]}


def previous_manifest(base: str | None) -> set[str]:
    return set(published_files(base))


def cmd_fill(args) -> int:
    policy = Policy.load()
    entries = read_lock()
    filler = Filler(args, policy)
    published = previous_manifest(filler.mirrors[0] if filler.mirrors else None)
    outcomes: list[Outcome] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for outcome in pool.map(filler.obtain, entries):
            outcomes.append(outcome)
    fatal = [o for o in outcomes if o.fatal]
    missing = [o for o in outcomes if not o.source and not o.fatal]
    by_component: dict[str, bool] = {}
    for outcome in outcomes:
        ok = bool(outcome.source)
        by_component[outcome.entry.component] = by_component.get(outcome.entry.component, True) and ok
    complete = {c for c, ok in by_component.items() if ok}
    locked = {e.path for e in entries}
    regressed = sorted(p for p in published if p in locked and p.rsplit("/", 1)[0] not in complete)
    sources: dict[str, int] = {}
    for outcome in outcomes:
        if outcome.source:
            sources[outcome.source] = sources.get(outcome.source, 0) + 1
    lines = [f"Locked files: {len(entries)}; obtained: {sum(sources.values())} "
             f"({', '.join(f'{k} {v}' for k, v in sorted(sources.items()))})",
             f"Components complete: {len(complete)} of {len(by_component)}",
             f"Missing files: {len(missing)}; sha256 mismatches from an upstream: {len(fatal)}"]
    if filler.unreachable_hosts():
        lines.append(f"Unreachable during this run: {', '.join(filler.unreachable_hosts())}")
    for outcome in fatal:
        lines.append(f"MISMATCH {outcome.entry.path}: {outcome.fatal}")
    for outcome in missing[:40]:
        lines.append(f"missing {outcome.entry.path}: {'; '.join(outcome.notes) or 'not found'}")
    if len(missing) > 40:
        lines.append(f"... and {len(missing) - 40} more missing files")
    for path in regressed[:40]:
        lines.append(f"REGRESSION {path} is published but could not be re-obtained")
    stats = None
    status = 0
    if fatal:
        lines.append("Refusing to publish: an upstream served a file that does not match the reviewed list.")
        status = 1
    elif regressed and not args.allow_regression:
        lines.append("Refusing to publish: the new site would drop files that are published now.")
        status = 1
    else:
        stats = build_site(Path(args.site), filler.store, entries, complete, policy)
        lines.append(f"Site: {stats['files']} artifact files ({stats['artifact_bytes'] / 1e6:.1f} MB), "
                     f"{stats['site_bytes'] / 1e6:.1f} MB with checksums and metadata "
                     f"({100 * stats['site_bytes'] / SITE_LIMIT:.1f}% of the bucket's 10 GB free allowance)")
        alert = size_alert(stats["site_bytes"])
        if alert:
            lines.append("ALERT: " + alert)
        elif stats["site_bytes"] > SITE_WARN:
            lines.append("WARNING: the site is above 80% of the bucket's free allowance.")
        if missing:
            status = 3
    report = "\n".join(lines)
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write("### Mirror fill\n\n```\n" + report + "\n```\n")
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as handle:
            handle.write(f"publishable={'true' if stats else 'false'}\n")
            handle.write(f"complete={'true' if stats and not missing else 'false'}\n")
            handle.write(f"site_bytes={stats['site_bytes'] if stats else 0}\n")
    return 0 if status == 3 and args.allow_incomplete else status


# --------------------------------------------------------------------------- publish


class JobToken:
    """The OpenID Connect token GitHub Actions gives this job, which is all the publisher asks for.

    A token lives a few minutes, so it is asked again before it gets old. It is never printed.
    """

    def __init__(self, audience: str, lifetime: float = 120):
        self.audience = audience
        self.lifetime = lifetime
        self.value = ""
        self.at = 0.0
        self.guard = threading.Lock()

    def request(self) -> str:
        url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        if not url or not bearer:
            raise MirrorError("no OpenID Connect token: publish runs in a job with `id-token: write`")
        separator = "&" if "?" in url else "?"
        try:
            body = http_get(f"{url}{separator}audience={urllib.parse.quote(self.audience, safe='')}",
                            headers={"Authorization": f"bearer {bearer}"})
            return json.loads(body)["value"]
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, ValueError) as exc:
            raise MirrorError(f"could not get the job's OpenID Connect token: {type(exc).__name__}") from exc

    def __call__(self, fresh: bool = False) -> str:
        with self.guard:
            if fresh or not self.value or time.monotonic() - self.at > self.lifetime:
                self.value = self.request()
                self.at = time.monotonic()
            return self.value


def publish_url(endpoint: str, path: str) -> str:
    return endpoint + "v1/files/" + "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))


def put_file(endpoint: str, path: str, data: bytes, token, attempts: int = 5) -> str:
    """Send one file to the publisher. Return "stored", or "present" when it already holds these bytes."""
    last = "error"
    for attempt in range(attempts):
        request = urllib.request.Request(publish_url(endpoint, path), data=data, method="PUT", headers={
            "User-Agent": USER_AGENT, "Authorization": f"Bearer {token(attempt > 0)}",
            "X-Sha256": hashlib.sha256(data).hexdigest(), "Content-Type": "application/octet-stream"})
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.loads(response.read())["status"]
        except urllib.error.HTTPError as exc:
            detail = exc.read(300).decode("utf-8", "replace").strip()
            last = f"HTTP {exc.code} {detail}"
            # 401 is a token that got old on the way; the rest of these are the host's own trouble
            if exc.code not in (401, 408, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524):
                break
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as exc:
            last = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
        time.sleep(min(30, 2 ** attempt))
    raise MirrorError(f"could not publish {path}: {last}")


def publish_site(site: Path, base: str, endpoint: str, token, jobs: int = 8, all_listings: bool = False) -> dict:
    """Send what the site holds and the published mirror lacks. Return what was done.

    A file goes first and its checksum files after it, the .sha256 last: a .sha256 that is
    published says the file and its other checksums are too, which is how a run that was cut short
    is picked up without sending everything again.

    Every jar goes before any .pom or .module. Gradle asks a repository for a version's files only
    once that repository has served the version's metadata, so a build that runs during a publish
    never finds a version here whose files are still on their way. It matters more than the moment
    it lasts: the host remembers that a .jar was not there for hours.

    The listings of the modules that changed follow, and the manifest goes last, so it never names
    a file that is not there.
    """
    manifest = json.loads((site / MANIFEST).read_text(encoding="utf-8"))["files"]
    published = published_files(base)
    todo = [item for item in manifest if published.get(item["path"]) != item["sha256"]]
    counts = {"stored": 0, "present": 0, "bytes": 0}
    guard = threading.Lock()

    def send(path: str, data: bytes) -> None:
        status = put_file(endpoint, path, data, token)
        with guard:
            counts[status] = counts.get(status, 0) + 1
            if status == "stored":
                counts["bytes"] += len(data)

    def artifact(item: dict) -> None:
        path = item["path"]
        marker = get_or_none(f"{base}{path}.sha256")
        if marker is not None and marker.decode("ascii", "replace").strip() == item["sha256"]:
            with guard:
                counts["present"] += 1
            return
        send(path, (site / path).read_bytes())
        for algorithm in sorted(CHECKSUMS, key=lambda name: name == "sha256"):
            send(f"{path}.{algorithm}", (site / f"{path}.{algorithm}").read_bytes())

    def listing(directory: str) -> None:
        path = f"{directory}/maven-metadata.xml"
        send(path, (site / path).read_bytes())
        for algorithm in CHECKSUMS:
            send(f"{path}.{algorithm}", (site / f"{path}.{algorithm}").read_bytes())

    def announces(item: dict) -> bool:
        return item["path"].endswith(METADATA_SUFFIXES)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        list(pool.map(artifact, [item for item in todo if not announces(item)]))
        list(pool.map(artifact, [item for item in todo if announces(item)]))
        chosen = manifest if all_listings else todo
        list(pool.map(listing, sorted({item["path"].rsplit("/", 2)[0] for item in chosen})))
    for name in ("index.html", MANIFEST):
        send(name, (site / name).read_bytes())
    return {"files": len(manifest), "new": len(todo), **counts}


def cmd_publish(args) -> int:
    base = args.base.rstrip("/") + "/"
    endpoint = args.endpoint.rstrip("/") + "/"
    done = publish_site(Path(args.site), base, endpoint, JobToken(base.rstrip("/")), args.jobs, args.all_listings)
    report = (f"Published to {base}: {done['new']} of {done['files']} files were new to the manifest; "
              f"{done['stored']} objects stored ({done['bytes'] / 1e6:.1f} MB), {done['present']} already there")
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write("### Mirror publish\n\n```\n" + report + "\n```\n")
    return 0


# --------------------------------------------------------------------------- verify-remote


def cmd_verify_remote(args) -> int:
    base = args.base.rstrip("/") + "/"
    entries = {e.path: e for e in read_lock()}
    published = sorted(previous_manifest(base) & set(entries))
    if args.paths:
        chosen = args.paths
    else:
        by_upstream: dict[str, list[str]] = {}
        for path in published:
            by_upstream.setdefault(entries[path].upstreams[0], []).append(path)
        chosen = []
        for paths in by_upstream.values():
            step = max(1, len(paths) // args.per_upstream)
            chosen += paths[::step][: args.per_upstream]
    failures = 0
    with tempfile.TemporaryDirectory() as work:
        for path in chosen:
            entry = entries.get(path)
            if entry is None:
                print(f"FAIL {path}: not in the lock")
                failures += 1
                continue
            temp = Path(work) / "file"
            status = download(base + path, temp)
            actual = sha256_file(temp) if status == "ok" else status
            sidecar = download(base + path + ".sha256", Path(work) / "sidecar")
            side = (Path(work) / "sidecar").read_text().strip() if sidecar == "ok" else sidecar
            ok = actual in entry.hashes and side == actual
            failures += not ok
            print(f"{'OK  ' if ok else 'FAIL'} {path} sha256={actual} sidecar={'match' if side == actual else side}")
    print(f"{len(chosen) - failures} of {len(chosen)} files verified over {base}")
    return 1 if failures or not chosen else 0


# --------------------------------------------------------------------------- check-size


def size_alert(site_bytes: int) -> str | None:
    """The alert for a site above 90% of the bucket's free allowance, or None below it."""
    if site_bytes <= SITE_ALERT:
        return None
    return (f"the site is {site_bytes / 1e6:.1f} MB, {100 * site_bytes / SITE_LIMIT:.1f}% of the "
            f"10 GB Cloudflare R2 stores without charge (alert above 90%, {SITE_ALERT / 1e6:.1f} MB). "
            f"Nothing stops at 100%, but the bucket is billed for what is above it: drop loader versions "
            f"the mods no longer build from their verification metadata, then run update-list (README, Size).")


def cmd_check_size(args) -> int:
    alert = size_alert(args.bytes)
    if alert:
        print(f"::error title=Mirror size::{alert}" if args.annotate else f"error: {alert}")
        return 1
    print(f"Site size {args.bytes / 1e6:.1f} MB, {100 * args.bytes / SITE_LIMIT:.1f}% of the "
          f"bucket's 10 GB free allowance (alert above 90%).")
    return 0


# --------------------------------------------------------------------------- main


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    update = sub.add_parser("update-list")
    update.add_argument("--metadata", nargs="*", help="local verification-metadata.xml files instead of sources.json")
    update.add_argument("--check", action="store_true", help="report drift from artifacts.lock without writing")
    update.add_argument("--summary", help="append a Markdown report to this file")
    update.add_argument("--pages", action="append",
                        help="published mirror to read POMs and locked .module files from before the upstreams "
                             "(every copy of a locked file is sha256-checked); may be given more than once, "
                             "default the mirror and where it was before; pass '' to use only the upstreams")
    update.add_argument("--relist", action="store_true",
                        help="ask the upstreams again which jars each POM-only version has, "
                             "instead of keeping what the current list holds for it")
    update.set_defaults(func=cmd_update_list)
    fill = sub.add_parser("fill")
    fill.add_argument("--site", required=True, help="output directory for the static Maven site")
    fill.add_argument("--store", required=True, help="persistent directory of verified files")
    fill.add_argument("--seed-gradle", action="append", default=[], help="Gradle files-2.1 cache to reuse (verified)")
    fill.add_argument("--seed-maven", action="append", default=[], help="Maven-layout directory to reuse (verified)")
    fill.add_argument("--pages", action="append",
                      help="URL of a published mirror, reused before any upstream; may be given more than once, "
                           "and the first is the one whose published files must not be dropped")
    fill.add_argument("--no-upstream", action="store_true", help="never contact the upstream repositories")
    fill.add_argument("--jobs", type=int, default=8)
    fill.add_argument("--allow-incomplete", action="store_true", help="exit 0 when some files are still missing")
    fill.add_argument("--allow-regression", action="store_true", help="publish even if published files would be dropped")
    fill.add_argument("--summary")
    fill.add_argument("--github-output")
    fill.set_defaults(func=cmd_fill)
    publish = sub.add_parser("publish")
    publish.add_argument("--site", required=True, help="the directory `fill` built")
    publish.add_argument("--base", default=DEFAULT_MIRROR, help="URL of the published mirror")
    publish.add_argument("--endpoint", default=DEFAULT_PUBLISHER, help="URL of the mirror's publisher")
    publish.add_argument("--jobs", type=int, default=8)
    publish.add_argument("--all-listings", action="store_true",
                         help="send every maven-metadata.xml again, not only those of modules with new files")
    publish.add_argument("--summary")
    publish.set_defaults(func=cmd_publish)
    verify = sub.add_parser("verify-remote")
    verify.add_argument("--base", required=True)
    verify.add_argument("--per-upstream", type=int, default=3)
    verify.add_argument("paths", nargs="*")
    verify.set_defaults(func=cmd_verify_remote)
    size = sub.add_parser("check-size")
    size.add_argument("--bytes", type=int, required=True, help="site size in bytes (fill's site_bytes output)")
    size.add_argument("--annotate", action="store_true", help="print the alert as a GitHub Actions error annotation")
    size.set_defaults(func=cmd_check_size)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except MirrorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

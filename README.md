# Plum Maven Mirror

A hash-checked, static Maven mirror of the openly licensed build dependencies that
[Quick Skin](https://github.com/The-Plum-Team/Quick-Skin-Mod) and
[Block Pops](https://github.com/The-Plum-Team/Block-Pops-Minecraft-Mod) resolve from modding
Maven hosts. It exists so that an outage of `maven.fabricmc.net`, `maven.neoforged.net`,
`maven.minecraftforge.net` or the other hosts below does not break those builds.

It is published with GitHub Pages at **https://the-plum-team.github.io/maven-mirror/**.

## How it works

1. `artifacts.lock` is the reviewed list: one line per file with its sha256, the upstream it comes
   from, its license and its Maven path. It is generated from the two mods' Gradle
   dependency-verification metadata (`gradle/verification-metadata.xml` on `master`), filtered by
   `policy.json`, plus the files that a locked Gradle `.module` declares with their sha256 (see
   "Using it from Gradle"). Nothing outside that list is ever published.
2. The [`Publish mirror`](.github/workflows/publish.yml) workflow runs weekly, on manual dispatch
   and whenever the list or policy changes on `main`. For every locked file it tries, in order, the
   verified store restored from the Actions cache, an optional seed release, the copy already
   published on Pages, and only then the upstream. **Only files that are still missing are
   downloaded from an upstream.**
3. Every candidate is checked against the sha256 in the list. A mismatching file from a cache, seed
   or the published site is discarded; **a mismatching file from an upstream stops the run and
   nothing is deployed.**
4. A version is published only when all of its locked files are present, so Gradle never finds a
   module's metadata here without its jars. The site holds the files plus `.md5`, `.sha1`,
   `.sha256` and `.sha512` checksum files, a `maven-metadata.xml` per module, and
   `mirror-manifest.json`. A run also refuses to deploy a site that would drop files that are
   published now (for example because Pages could not be read back).
5. After deploying, the workflow downloads a sample of files from each upstream over the Pages URL
   and checks their sha256 against the list.

The workflows use only the Python standard library, pin every action by commit SHA and run with
`permissions: {}` by default; only the deploy job gets `pages: write` and `id-token: write`.

## What is mirrored

| Upstream | Groups | Licenses |
| --- | --- | --- |
| `maven.fabricmc.net` | `net.fabricmc` (Loader, Intermediary, Mixin, tooling), `net.fabricmc.fabric-api`, `net.fabricmc.unpick` | Apache-2.0, CC0-1.0, MIT, LGPL-3.0, EPL-2.0, MPL-2.0 |
| `maven.architectury.dev` | `dev.architectury` (API, Loom, Transformer, tooling), Loom and plugin markers | LGPL-3.0, MIT, Apache-2.0, EPL-2.0 |
| `maven.kikugie.dev/releases` | `dev.kikugie` Stonecutter and its plugin marker | LGPL-3.0 |
| `maven.neoforged.net/releases` | `net.neoforged` NeoForge, FancyModLoader, Bus, CoreMods, AccessTransformers, InstallerTools, JarJar, SRGUtils, MergeTool, AutoRenamingTool; `cpw.mods` | LGPL-2.1, LGPL-3.0, MIT |
| `maven.minecraftforge.net` | `net.minecraftforge` Forge, FML modules and tooling | LGPL-2.1, MIT |
| `dl.cloudsmith.io/public/geckolib3` | `software.bernie.geckolib`, `com.geckolib` | MIT |

Each include rule in `policy.json` names its license and links the upstream's license file. Forge
and NeoForge are mirrored as their projects license and publish them (LGPL-2.1, including their
patch artifacts, whose authorship the Forge license assigns to the project). Checked on
2026-10-11 for Forge 1.20.1-47.4.9 and NeoForge 21.1.251: no jar holds a `net/minecraft` or
`com/mojang` class or source file. The `userdev` and `installer` jars hold binary diffs and source
patches against Minecraft (`joined.lzma`, `client.lzma`, `server.lzma`, `patches/`). The
`universal` and `sources` jars hold the loaders' own generated JSON under `assets/minecraft` and
`data/minecraft` (tags, loot tables, recipes and advancements that the loader overrides). These are
the files their projects publish for everyone on their own Maven repositories.

Maven Central and the Gradle Plugin Portal are not mirrored: they are not the hosts whose outages
this addresses.

## What is NOT mirrored

- **Minecraft and anything from Mojang**, whatever its license: `com.mojang:*`, `net.minecraft:*`
  and Mojang's patched `org.lwjgl:lwjgl-freetype`. Minecraft jars, assets and mappings are
  downloaded by Loom from Mojang and are never stored here.
- **Minecraft-derived decompilation data with no clear license**: NeoForm (`net.neoforged:neoform`,
  no license in its repository) and MCPConfig/MCInjector (`de.oceanlabs.mcp:*`).
- **Anything whose license could not be confirmed**: currently `com.eliotlash.mclib:mclib`.
- **Versions the mods disagree about**: when the two mods' verification metadata record different
  sha256 values for the same file, the whole version stays on its upstream until they agree.

`excluded.txt` lists every such component seen in the mods' metadata. Those still come from their
upstreams, so an outage of the NeoForge or Forge Maven can still block NeoForm/MCPConfig downloads
on a machine that does not have them cached.

## Using it from Gradle

Declare the mirror before the upstreams, restricted to the mirrored groups, and keep the upstream
repositories after it. Gradle uses the first repository that has a module and moves on when this
one answers 404, so anything not mirrored still resolves from its upstream:

```kotlin
maven("https://the-plum-team.github.io/maven-mirror/") {
    name = "PlumMavenMirror"
    // Only the files in the verification metadata are mirrored: a module's .module file without
    // the .pom that merely points to it, so Gradle must look for the .module first.
    metadataSources { gradleMetadata(); mavenPom() }
    mavenContent { releasesOnly() }
    content {
        includeGroupByRegex("net\\.fabricmc(\\..*)?")
        includeGroupByRegex("dev\\.architectury(\\..*)?")
        includeGroup("architectury-plugin")
        includeGroupByRegex("dev\\.kikugie(\\..*)?")
        includeGroupByRegex("net\\.neoforged(\\..*)?")
        includeGroupByRegex("net\\.minecraftforge(\\..*)?")
        includeGroup("cpw.mods")
        includeGroupByRegex("software\\.bernie(\\..*)?")
        includeGroup("com.geckolib")
    }
}
```

The mirror deliberately holds no file that is not in the reviewed list, so a module published with
Gradle Module Metadata has its `.module` file here but not the `.pom` stub that Gradle fetches first
by default; `metadataSources { gradleMetadata(); mavenPom() }` on this repository only makes Gradle
ask for the `.module` directly.

The fallback works per version, not per file. Once Gradle finds a version's `.module` or `.pom`
here, it downloads that version's other files from here too and does not try the upstream for
them. A build that needs a file of a mirrored version that is not here fails with `Could not find`,
although the upstream has the file. Measured on 2026-10-11: Quick Skin's `neoforge-26.3` lane
builds without the mirror but failed with it on `neoforge-26.3.0.3-beta-sources.jar`, because only
Block Pops' metadata records that NeoForge version and it does not record the sources jar.

To close most of that gap, `update-list` also locks every file that a locked `.module` declares,
except javadoc jars. It reads each `.module` from Pages or its upstream, checks it against its
locked sha256, and trusts the sha256 the `.module` gives for each of its files. Versions published
with only a `.pom` cannot be completed this way: for example
`net.fabricmc:fabric-loader:0.19.3:sources` still fails with the mirror. Under strict verification
such a file would fail anyway until its hash is recorded, but a pull request that records a new file
of a `.pom`-only mirrored version cannot build until that change reaches the mods' `master` and
this mirror republishes. Such a change needs a way for the build to skip the mirror, which the mods
do not have yet.

Gradle dependency verification still checks every file against each mod's own
`verification-metadata.xml`, whichever repository served it. That check, not this repository, is
the final guarantee, which is why the mirror is safest with strict verification enabled.

Dynamic versions are the remaining gap. For a dynamic version Gradle lists versions from every
repository that may hold the module, and a listing error fails the build even when the mirror holds
the version it would pick. Two such lookups exist today:

- Architectury Loom resolves `dev.architectury:mixin-patched:0.8.5.+` for Forge projects, so Forge
  lanes still need `maven.architectury.dev`.
- Architectury's transformer classpath asks for `net.fabricmc:fabric-loader:+` unless the build
  forces it. Block Pops forces it to its matrix-owned loader; Quick Skin does not yet, so Quick
  Skin's common transform still needs `maven.fabricmc.net`.

Measured on a rig with every mirrored version forbidden upstream: Block Pops' Fabric 1.20.1,
NeoForge 1.21.4 and NeoForge 26.3 lanes build with `maven.fabricmc.net`, `meta.fabricmc.net`,
`maven.architectury.dev` and `maven.kikugie.dev` unreachable, and its Forge 1.20.1 lane builds with
only the Fabric and Kikugie hosts unreachable.

If Pages itself is unreachable Gradle fails instead of falling back (it only falls back on 404), so
the mirror moves the single point of failure for these groups from the modding hosts to GitHub
Pages. A build with a warm Gradle cache and `--offline` needs neither.

## Size

GitHub Pages allows a 1 GB site and 100 MB per file. `fill` refuses any file over 100 MB, fails
above 1 GB and warns above 80%; the workflow summary reports the size on every run. Above 90%
(966.4 MB) the publish workflow's `size` job fails after the deploy, so the site still goes out and
the failed run is the alert (`python3 scripts/mirror.py check-size --bytes N` runs the same check). Most of the
size is NeoForge and Forge installer, universal, userdev and sources jars, roughly 25 MB per loader
version; when the list grows near the limit, versions the mods no longer build should be dropped
from their verification metadata first.

## Maintaining the list

```sh
python3 scripts/mirror.py update-list           # regenerate artifacts.lock and excluded.txt
python3 scripts/mirror.py update-list --check   # report drift without writing
python3 -m unittest discover -s tests
```

Review the diff of `artifacts.lock` and `excluded.txt` in a pull request: every new hash is a new
file the mirror will serve. The `Check` workflow reports drift between the lock and the mods'
current metadata on every pull request. Adding a module or a group is a change to `policy.json`
that must cite the upstream's license.

### Seeding while an upstream is down

`fill` can reuse files from a Gradle cache (`--seed-gradle ~/.gradle/caches/modules-2/files-2.1`)
or a Maven-layout directory (`--seed-maven DIR`). To fill Pages while an upstream is unreachable,
build a store locally, publish it as `seed-*.tar` assets of a release in this repository, and run
`Publish mirror` with `seed_release` set to that tag. Seeds are untrusted: each file is checked
against the list exactly like a download.

```sh
python3 scripts/mirror.py fill --site /tmp/site --store /tmp/store \
  --seed-gradle ~/.gradle/caches/modules-2/files-2.1 --no-upstream --allow-incomplete
tar -C /tmp/store -cf seed-1.tar .
```

## License

No license has been chosen yet for the scripts and workflows in this repository. Mirrored artifacts
keep their own upstream licenses, listed per file in `artifacts.lock` and `mirror-manifest.json`;
this mirror redistributes them unmodified.

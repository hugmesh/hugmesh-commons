# Releasing hugmesh-commons

`net.hugmesh:hugmesh-commons` is **link 3 of 4** in the org's Maven publish chain:

```
hugmesh-build-config 0.6.0-beta.1  ->  hugmesh-parent 2.9.0-beta.1  ->  hugmesh-commons 2.2.0-beta.1  ->  hugmesh-auth-core 2.6.0-beta.1
```

Each link is published in that order, and each one only after the link before it is
readable from GitHub Packages: this pom's `<parent>` is `hugmesh-parent:2.9.0-beta.1`, so
commons cannot even build in CI until the parent beta is published.

Until 2026-09-17 this repo had **no GitHub workflow at all**
(`gh api repos/hugmesh/hugmesh-commons/contents/.github/workflows` → 404), which made it
the hard stop in the chain: nothing downstream could be published because nothing could
publish *it*. That is hugmesh/hugmesh-commons#4.

## Versions and how a beta is cut (2026-10-21)

The version is `MAJOR.MINOR.PATCH-beta.N`, never SNAPSHOT and never with `+build` metadata.
2.1.0 was pinned by fourteen consumers and its content changed after the pin, so the
betas go on the next minor: the first is **`2.2.0-beta.1`**. A fix during the beta raises N
(`2.2.0-beta.2`), not PATCH. Maven orders these as
`2.1.0 < 2.2.0-beta.1 < 2.2.0-beta.2 < 2.2.0-beta.10 < 2.2.0`.

A publish is a **tag**, pushed by a person, whose name is `v` plus the `<version>` in
`pom.xml`:

```
git tag -a v2.2.0-beta.1 -m "hugmesh-commons 2.2.0-beta.1" <commit on main>
git push origin v2.2.0-beta.1
```

What `release.yml` does with each event:

| Event | What happens |
|---|---|
| push of tag `v<version>` | version guard, `verify`, `deploy` (jar + `tests` classifier), GitHub Release marked prerelease and not latest |
| `workflow_dispatch` on a `v*` tag | the same; this is the re-run path, and the release step skips itself if that GitHub Release exists |
| `workflow_dispatch` on `main` | version guard and `verify` only; nothing is published |
| push to a branch, any other ref | nothing starts (no branch trigger), or the version guard refuses it |

The version guard fails the run when the tag does not equal `pom.xml`'s version, when the
version is not `MAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH-beta.N`, and on any ref other than
`main` or a `v*` tag.

**Runner.** Every job uses one `runs-on` line: the self-hosted runner named by the
repository variable `RUNS_ON_PUBLISH` (a JSON array such as `["self-hosted","Linux","X64"]`)
for a non-pull-request event on `main` or a release tag, and hosted `ubuntu-latest` for
everything else. When `RUNS_ON_PUBLISH` is not set, everything runs on hosted runners;
deleting it is the off switch. The older `RUNS_ON` variable is no longer read by anything
here. Because a self-hosted runner shares its host's home directory, the workflow keeps
setup-java's `settings.xml` and the Maven local repository under the runner's temporary
directory, points `mvnw`'s own Maven download there too (`MAVEN_USER_HOME`), and never
writes to `~/.m2`.

The full story — what a release IS in this org, and the operator's launch-day click list —
is in **`hugmesh-auth-core/RELEASING.md`**. This file is what is specific to commons.
Written against operator decision 27 (hugmesh-generator#347, 2026-09-17): *"B for the
mechanism, A prepared"* — source-building stays the mechanism, the publish path is real but
unfired.

## Two artifacts, not one

`deploy` publishes **`hugmesh-commons-<version>.jar` and `hugmesh-commons-<version>-tests.jar`**.
The second comes from maven-jar-plugin's `test-jar` goal, bound in `pom.xml` as the
`shared-test-base` execution, and it is not optional: `hugmesh-auth-core`'s test scope
compiles against `net.hugmesh:hugmesh-commons:<version>:tests` for `PostgresTestSupport`, the
one shared Testcontainers-Postgres base the fleet uses instead of a per-repo copy.

**`-DskipTests` is correct; `-Dmaven.test.skip=true` is not.** `skipTests` skips test
*execution* and still compiles `src/test`, which is what the `test-jar` goal packages.
`maven.test.skip` skips compilation too, so `target/test-classes` is empty and the `tests`
classifier publishes as an **empty jar** — a publish that reports success and breaks the
next link at test-compile, where it reads like an auth-core problem.
`ReleasePublishGuardTest` fails the build if that flag appears in the workflow, or if the
`test-jar` binding disappears from `pom.xml`.

## Why the repository URL is in a CI-only settings file and not in pom.xml

This project's effective repository list is **Maven Central alone**, and its own
`<parent>` (`net.hugmesh:hugmesh-parent`) is 404 there — so a CI build cannot even
resolve its parent. The route is `.github/maven-ci-settings.xml`, passed with `-s` by
`release.yml` and by nothing else.

Not `pom.xml`, because `maven.pkg.github.com` requires authentication even to **read**.
Measured 2026-09-17:

```
$ curl -s -o /dev/null -w '%{http_code}\n' \
    https://maven.pkg.github.com/hugmesh/hugmesh-parent/net/hugmesh/hugmesh-parent/2.8.0/hugmesh-parent-2.8.0.pom
401
$ curl ... -H "Authorization: Bearer $(gh auth token)" <same URL>
401      # classic token; scopes gist/project/read:org/repo/workflow — no read:packages
```

A `<repositories>` entry in the pom would therefore turn every unauthenticated
`./mvnw verify` and every `hugmesh-generator/tests/stack/m2-bootstrap.sh` cold build into a
401. That cold build is how the compose stack builds this library today, from pinned commit
SHAs, and decision 27 deliberately **keeps** it as the mechanism.

Two details in that file that are easy to get wrong:

- **`<pluginRepositories>` as well as `<repositories>`.** `net.hugmesh:hugmesh-build-config`
  is not a project dependency — `hugmesh-parent` puts it on the PMD / Checkstyle / SpotBugs
  **plugin** classpaths, and Maven resolves a plugin's `<dependencies>` from the **plugin**
  repositories. A repositories-only file resolves the parent POM and then dies at `verify`
  on the ruleset jar.
- **A `<server><id>github</id>` inside it.** `-s` *replaces* the user settings file, so the
  entry `actions/setup-java` generates into `~/.m2/settings.xml` is invisible, and the
  deploy step's `-DaltDeploymentRepository=github::default::…` would upload with no
  credential.

Measured on this branch, offline, so nothing from the network can contribute:

```
$ ./mvnw -o -q -B -ntp help:evaluate -Dexpression=project.repositories -DforceStdout
    <id>central</id>                        # unchanged: developer builds, m2-bootstrap.sh
$ ./mvnw -o -q -B -ntp -s .github/maven-ci-settings.xml help:evaluate -Dexpression=project.repositories -DforceStdout
    <id>github-hugmesh-build-config</id>
    <id>github-hugmesh-parent</id>
    <id>central</id>
$ ./mvnw -o -q -B -ntp -s .github/maven-ci-settings.xml help:evaluate -Dexpression=project.pluginRepositories -DforceStdout
    <id>github-hugmesh-build-config</id>    # ...and the same two as PLUGIN repositories
    <id>github-hugmesh-parent</id>
    <id>central</id>
```

## Cross-repo package reads — the grant that going public does NOT perform

This repo's release build resolves `net.hugmesh` artifacts published from **other**
repositories (`hugmesh-build-config` on the analyser plugin classpaths, `hugmesh-parent` as this pom's own `<parent>`). `secrets.GITHUB_TOKEN` is scoped to the repository whose
workflow is running, and GitHub does not extend it across repositories for package reads:
the build must present a token carrying `read:packages`. That token is the secret
**`PACKAGES_READ_TOKEN`** (operator decision 90a = B, hugmesh-generator#347, answered
2026-09-23).

The first cut of this round wired every upstream `<server>` to `${env.GITHUB_TOKEN}`, and
what makes that worse than an ordinary missing step is the **shape of its failure**. Maven
reports it as `Could not resolve net.hugmesh:...`, which is the same string this file and
the workflow comments teach a reader to read as *"the upstream is not published yet"*. The
natural response — re-publish the upstream — burns a version, succeeds, and hits the same
wall. So:

- **The read credential is its own env var.** `.github/maven-ci-settings.xml` authenticates
  the `github-hugmesh-*` upstream servers with `${env.UPSTREAM_PACKAGES_*}`, injected by
  `release.yml` as `${{ secrets.PACKAGES_READ_TOKEN || secrets.GITHUB_TOKEN }}`. The
  `github` **deploy** server keeps the automatic `${env.GITHUB_TOKEN}` — a workflow may
  always write packages for its own repository, so the deploy half needs no operator secret.
- **A preflight step names the failure correctly.** Before maven runs, `release.yml` probes
  each upstream's `maven-metadata.xml` with the exact credential maven will use, and tells
  `401`/`403` (*cannot authenticate; NOT "unpublished"*) apart from `404` (*nothing published
  there yet, **or** published and invisible to this credential — GitHub masks an unauthorised
  read of a private package as 404*). Exercised against the live registry on 2026-09-18 with
  an invalid credential: it emitted the `401` branch for every upstream and exited 1.

**Neither of those grants anything.** The grant is the **`PACKAGES_READ_TOKEN`**
secret. **Decided 2026-09-23, decision 90a = B:** one **classic** personal access token with
the `read:packages` scope, stored as the secret `PACKAGES_READ_TOKEN`, separate from
`RELEASE_CHAIN_TOKEN`, created by the operator and **kept** as a standing secret, not a
launch-day stopgap to be retired afterwards. Scope: a REPOSITORY secret on each repo whose `release.yml` reads it (`hugmesh-parent`, `hugmesh-commons`, `hugmesh-auth-core`), because the org is on the Free plan and the repos are private, and an org secret is understood not to reach private repos on that plan (from GitHub's plan limits, untested; see `hugmesh-auth-core/RELEASING.md` §6.2 "Secret scope"). It must be classic: GitHub's docs say *"GitHub
Packages only supports authentication using a personal access token (classic)"* (read from
the docs, not tested). It does not depend on any package existing first, so it serves a cold
first publish. `release.yml` already prefers it and falls back to `GITHUB_TOKEN` only when it
is absent; that fallback is **not a route**, because it cannot read another repository's
packages (above).

- *Not the plan:* per-package **Manage Actions access** grants ("route A", which this file
  offered as an option before 2026-09-23: on each upstream package, add this repository).
  GitHub's docs list that setting only for container, npm, NuGet and RubyGems packages and
  say Maven packages inherit their repository's permissions, so it is probably not offered
  for these Maven packages at all. That is read from the docs, not tested, because no
  `net.hugmesh` package is known to have been published. Even where it exists it can only be
  granted after a package is published, so it could never serve a first run. Where a
  `release.yml` comment or preflight message in this repo still offers it, that text predates
  decision 90a.

Full click list: `hugmesh-auth-core/RELEASING.md` §6.2. **Nothing here has been executed** —
no Actions job in this org starts at all today (billing; `hugmesh-auth-core/RELEASING.md`
§6.1), and no `PACKAGES_READ_TOKEN` exists (measured 2026-10-07: `gh api repos/hugmesh/<repo>/actions/secrets` and `.../actions/organization-secrets` both answer 200 with `total_count` 0, so `PACKAGES_READ_TOKEN` is absent, not merely inferred; the org-level listing `/orgs/hugmesh/actions/secrets` still answers 403).

## The guard

`ReleasePublishGuardTest` (16 checks) pins all of the above by **parsing** `release.yml`,
`maven-ci-settings.xml` and `pom.xml` rather than grepping them — a guard that matches one
*spelling* of a config file fails open on every other spelling, and a flag that survives
only in a YAML comment is not a flag. Run it on its own:

```
./mvnw -o test -Dtest=ReleasePublishGuardTest
```

It was mutation-tested on 2026-09-17: production was broken eight ways (workflow deleted,
push trigger added, `-s` dropped, `<pluginRepositories>` deleted, packages URL moved into
`pom.xml`, `-DaltDeploymentRepository` dropped, `-DskipTests` swapped for
`-Dmaven.test.skip=true`, `test-jar` unbound) and the guard **failed on all eight**, with
no fail-open.

## What a human must still verify

- **This workflow has never run.** It did not exist until now, and
  `gh run list --repo hugmesh/hugmesh-commons` → empty.
- **No Actions job in this org starts at all today.** The annotation on the most recent runs
  across the org is *"The job was not started because recent account payments have failed or
  your spending limit needs to be increased."* Private-repo Actions minutes are billed;
  public-repo minutes are free, so this dissolves when the repos go public.
  `hugmesh-auth-core/RELEASING.md` §6.1 has the exact `gh api` calls.
- **The Testcontainers step is unproven on a runner.** `PostgresTestSupport` starts a real
  Postgres; `ubuntu-latest` ships a working Docker daemon, so `verify` is *expected* to run
  the full suite — expected, not observed.
- **Whether anything is already published is unknown, not "nothing".** Confirming needs a
  token with `read:packages`; this box's has none
  (`gh api /orgs/hugmesh/packages?package_type=maven` → HTTP 403).

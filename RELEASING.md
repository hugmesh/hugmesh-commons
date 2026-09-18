# Releasing hugmesh-commons

`net.hugmesh:hugmesh-commons` is **link 3 of 4** in the org's Maven publish chain:

```
hugmesh-build-config 0.5.0  ->  hugmesh-parent 2.8.0  ->  hugmesh-commons 2.1.0  ->  hugmesh-auth-core 2.5.1
```

Until 2026-09-17 this repo had **no GitHub workflow at all**
(`gh api repos/hugmesh/hugmesh-commons/contents/.github/workflows` → 404), which made it
the hard stop in the chain: nothing downstream could be published because nothing could
publish *it*. That is hugmesh/hugmesh-commons#4.

The full story — what a release IS in this org, and the operator's launch-day click list —
is in **`hugmesh-auth-core/RELEASING.md`**. This file is what is specific to commons.
Written against operator decision 27 (hugmesh-generator#347, 2026-09-17): *"B for the
mechanism, A prepared"* — source-building stays the mechanism, the publish path is real but
unfired.

## Two artifacts, not one

`deploy` publishes **`hugmesh-commons-2.1.0.jar` and `hugmesh-commons-2.1.0-tests.jar`**.
The second comes from maven-jar-plugin's `test-jar` goal, bound in `pom.xml` as the
`shared-test-base` execution, and it is not optional: `hugmesh-auth-core`'s test scope
compiles against `net.hugmesh:hugmesh-commons:2.1.0:tests` for `PostgresTestSupport`, the
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
`<parent>` (`net.hugmesh:hugmesh-parent:2.8.0`) is 404 there — so a CI build cannot even
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
401. That cold build is how the compose lane builds this library today, from pinned commit
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
each upstream package must name this repository under **Manage Actions access** in its own
package settings, or the build must present a token carrying `read:packages`.

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

**Neither of those grants anything.** On launch day the operator picks one of two routes,
and **that decision has not been made**:

- **Route A, no secret:** on each upstream package → *Package settings* → **Manage Actions
  access** → add this repository. Only possible **after** that package exists, so it cannot
  be set up ahead of a cold first publish.
- **Route B, one secret, works cold:** a PAT with `read:packages` on the hugmesh org stored
  as **`PACKAGES_READ_TOKEN`** (org secret, or a repo secret here). `release.yml` prefers it
  and falls back to `GITHUB_TOKEN`. This is the route for a launch-day single-click publish.

Full click list: `hugmesh-auth-core/RELEASING.md` §6.2. **Nothing here has been executed** —
no Actions job in this org starts at all today (billing; `hugmesh-auth-core/RELEASING.md`
§6.1), and no `PACKAGES_READ_TOKEN` exists (inferred — listing secrets needs org-admin and
answers 403 from this box).

## The guard

`ReleasePublishGuardTest` (7 checks) pins all of the above by **parsing** `release.yml`,
`maven-ci-settings.xml` and `pom.xml` rather than grepping them — a guard that matches one
*spelling* of a config file fails open on every other spelling, and a flag that survives
only in a YAML comment is not a flag. Run it on its own:

```
./mvnw -o test -Dtest=ReleasePublishGuardTest
```

It was mutation-tested on 2026-09-17: production was broken eight ways (workflow deleted,
push trigger added, `-s` dropped, `<pluginRepositories>` deleted, packages URL moved into
`pom.xml`, `-DaltDeploymentRepository` dropped, `-DskipTests` swapped for
`-Dmaven.test.skip=true`, `test-jar` unbound) and the guard went **red on all eight**, with
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

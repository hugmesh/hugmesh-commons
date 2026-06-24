# snapdragon-commons

The shared, **canonical** Snapdragon security / tenancy / config / web building
blocks. These classes were previously copied byte-for-byte (modulo package + access
modifiers) into each reactive BFF (`snapdragon-federation-api`,
`snapdragon-admin-bff-api`, `snapdragon-user-bff-api`, `snapdragon-owncast-bff-api`,
…). This library is the single source of truth; the per-repo copies are replaced by a
dependency on it.

It sits at the bottom of the shared-artifact stack. `snapdragon-auth-core` (the shared
account / session / MFA / Casdoor-admin infrastructure consumed by `snapdragon-user-bff-api`
and `snapdragon-admin-bff-api`) depends on **this** library for its security and tenancy
primitives; every reactive service depends on it directly for the security/tenancy/web
classes below.

## Coordinates

```
groupId:    systems.snapdragon
artifactId: snapdragon-commons
version:    2.0.0
packaging:  jar
```

Child of `systems.snapdragon:snapdragon-parent:2.4.0` (the metapom), which pins the
ecosystem baseline: **Spring Boot 4.0.2 / Spring Cloud 2025.1** on Java.

## Contents

| Class | Package | Role |
|-------|---------|------|
| `Roles` | `systems.snapdragon.commons.security` | JWT role / domain / MFA-stamp extraction. |
| `RoleName` | `systems.snapdragon.commons.security` | closed enum of the four base Casdoor role tokens (`user`/`mod`/`admin`/`superadmin`); fail-closed `fromWire`/`require`/`isBaseRole` with the lowercase on-the-wire value preserved as a live contract. |
| `CasdoorAuthorities` | `systems.snapdragon.commons.security` | Casdoor JWT → Spring authorities converter (the RESERVED-PREFIX injection guard lives here). |
| `DomainRegistry` | `systems.snapdragon.commons.security` | issuer-URI → brand/domain map; single-issuer back-compat + multi-brand fail-closed; `knownDomains`/`isKnownDomain` validation. |
| `PrincipalDomain` | `systems.snapdragon.commons.security` | instance-based, SUPERADMIN-aware per-request tenant scope (was the federation/admin `DomainScope`). |
| `DomainScope` | `systems.snapdragon.commons.tenancy` | static SQL-predicate utility (`andPredicate`/`isUnscoped`) for per-domain repositories (was the user/owncast `DomainScope`). |
| `TenancyResourceServerConfig` | `systems.snapdragon.commons.config` | config-gated, backward-compatible multi-issuer (per-brand Casdoor) resource-server wiring. |
| `ApiException` | `systems.snapdragon.commons.web` | the BFF `{"error": msg}` exception with the full union of HTTP-status factories. |

## Preserved security behaviours

1. JWT roles-claim → `ROLE_` mapping (`Roles.fromJwt` + the converter).
2. `isAdmin` (claim or legacy boolean) → `ROLE_ADMIN`.
3. `DOMAIN_<x>` derived ONLY from the cryptographically-validated issuer.
4. **RESERVED_PREFIXES guard** — `ROLE_` / `DOMAIN_` / `MFA_SATISFIED` permission
   strings are dropped (no authority injection / cross-tenant escalation / forged MFA).
5. **Fail-closed domain resolution** — unknown issuer → `null`; `domainOf(authorities)`
   returns `null` on zero or >1 `DOMAIN_` (injection signature).
6. SUPERADMIN exempt from per-domain scoping (`Roles.isSuperadmin`, `PrincipalDomain`).
7. `MFA_SATISFIED` derived only from a fresh, BFF-written `mfa_satisfied_at` stamp
   (future / stale / malformed rejected; ships dark by default).
8. Multi-issuer is OPT-IN and backward-compatible (`isMultiIssuer()` /
   `@ConditionalOnExpression`).

All eight are covered by the unit tests under `src/test/java`.

## What stays per-repo

`SecurityConfig` stays in each service: its `authorizeExchange` route matchers
(`/bff/admin/**`, `/bff/user/**`, `/bff/owncast/**`, `/api/federation/**`) and CSRF /
cookie handling are per-repo. Each repo's `SecurityConfig` wires the shared
`CasdoorAuthorities` / `DomainRegistry` and (optionally) `TenancyResourceServerConfig`,
then declares its own routes. The per-repo security-slice test scaffolding
(`SecuritySliceSupport`) also stays per-repo because it constructs the per-repo
`SecurityConfig`.

## Using it

```xml
<dependency>
  <groupId>systems.snapdragon</groupId>
  <artifactId>snapdragon-commons</artifactId>
  <!-- version managed by snapdragon-parent -->
</dependency>
```

Then delete the repo-local copies of the classes above and rewrite imports
(`systems.snapdragon.<repo>.security.Roles` → `systems.snapdragon.commons.security.Roles`,
etc.). Note the two erasure-distinct authority overloads:
`Roles.isSuperadmin(Set<String>)` / `Roles.domainOf(Set<String>)` (federation's
authority-string form) become `Roles.isSuperadminNames(...)` / `Roles.domainOfNames(...)`.

## Build / publish

`./mvnw verify` compiles and runs the unit tests. The build also publishes a
**test-jar** alongside the main jar so consumers can depend on
`systems.snapdragon:snapdragon-commons:2.0.0:tests` (test scope) and `extends
PostgresTestSupport` — ONE shared Testcontainers-Postgres base (singleton container,
fresh database per test class) for the whole org instead of re-copying it per repo.

CI publishes the jar to the GitLab
Maven Package Registry on the default branch / on a tag via
`./mvnw deploy -s settings.xml`, authenticating with the GitLab-injected
`CI_JOB_TOKEN` — **no secret is committed**. (Snapdragon CI is GitLab; there are no
GitHub Actions.) For local development, `./mvnw install` writes the jar to `~/.m2` so
sibling repos resolve it offline.

## Current State

- **At `2.0.0` on the unified ecosystem baseline** — Spring Boot 4.0.2 / Spring Cloud
  2025.1, child of `snapdragon-parent:2.4.0`. This was bumped from `1.0.0` as part of the
  org-wide Boot 4 migration (`snapdragon-federation-api` is the migrated exemplar).
- **Bottom of the shared-artifact stack.** The new `snapdragon-auth-core:2.0.0` (shared
  account / session / MFA / Casdoor-admin infrastructure) depends on this library;
  `snapdragon-auth-core` is in turn consumed by `snapdragon-user-bff-api` and
  `snapdragon-admin-bff-api`. All reactive BFFs depend on commons for the
  security / tenancy / config / web primitives above.
- **Auth-model alignment.** In the current SSO design, `login-ui` drives the Casdoor
  OIDC authorization-code (PKCE) flow, `user-bff` performs the server-side code→token
  exchange and holds per-session JWT custody, and the browser only ever holds an opaque
  `bff_`-prefixed session — the user never sees their Casdoor JWT. The gateway is a pure
  Casdoor-JWT OAuth2 resource server; a pre-security exchange filter swaps `bff_` for the
  internal custody JWT so the JWT validation + role gate (and the `CasdoorAuthorities` /
  `Roles` / `DomainRegistry` logic in this library) run unchanged. Login / session /
  account logic is being relocated from `admin-bff` to `user-bff`, with the shared core
  extracted to `snapdragon-auth-core`; this library is unchanged by that move — it remains
  the JWT→authorities + tenancy substrate underneath both.
- **`MFA_SATISFIED` is load-bearing.** Behaviour 7 (the fresh `mfa_satisfied_at` stamp →
  `MFA_SATISFIED` authority, with the reserved-prefix guard preventing forgery) is the
  mechanism by which BFF-driven MFA challenges are honoured even in the opaque-session
  bridge; it ships dark by default until MFA is enabled.
- All eight preserved security behaviours remain covered by unit tests; the GitLab CI
  publish path to the Maven Package Registry is in place.

## Roadmap

This library underpins several in-flight / designed platform initiatives; new shared
primitives land here as they generalise:

- **SSO end-to-end live + e2e** — the opaque `bff_` ↔ custody-JWT bridge proven through the
  gateway resource server with the `CasdoorAuthorities` / `DomainRegistry` path; full
  end-to-end e2e in progress.
- **MFA** (WebAuthn + TOTP + recovery, per-role defaults, step-up) — built on the existing
  `MFA_SATISFIED` stamp derivation (behaviour 7) plus the reserved-prefix guard.
- **Multi-tenancy / multi-brand superadmin** — per-domain CA + per-brand gateway/BFF/UI;
  exercises the opt-in multi-issuer (`TenancyResourceServerConfig`) and fail-closed
  domain resolution already present here.
- Downstream platform work that consumes these primitives without changing them:
  data-driven gateway route authorization (`gateway_route_access`), encrypted versioned
  backups, egress VPN drop-in, per-node attached storage, desktop app governance, workload
  console, device-license registry, the games app-store, A/V via coturn/TURN, and OWASP
  pen-test + nuclei in CI.

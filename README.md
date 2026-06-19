# snapdragon-commons

The shared, **canonical** Snapdragon security / tenancy / config / web building
blocks. These classes were previously copied byte-for-byte (modulo package + access
modifiers) into each reactive BFF (`snapdragon-federation-api`,
`snapdragon-admin-bff-api`, `snapdragon-user-bff-api`, `snapdragon-owncast-bff-api`,
…). This library is the single source of truth; the per-repo copies are replaced by a
dependency on it.

## Coordinates

```
groupId:    systems.snapdragon
artifactId: snapdragon-commons
version:    1.0.0
packaging:  jar
```

Child of `systems.snapdragon:snapdragon-parent:1.0.0`.

## Contents

| Class | Package | Role |
|-------|---------|------|
| `Roles` | `systems.snapdragon.commons.security` | JWT role / domain / MFA-stamp extraction. |
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

`./mvnw verify` compiles and runs the unit tests. CI publishes the jar to the GitLab
Maven Package Registry on the default branch / on a tag via
`./mvnw deploy -s settings.xml`, authenticating with the GitLab-injected
`CI_JOB_TOKEN` — **no secret is committed**. For local development, `./mvnw install`
writes the jar to `~/.m2` so sibling repos resolve it offline.

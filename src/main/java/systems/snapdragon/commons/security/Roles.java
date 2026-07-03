package systems.snapdragon.commons.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * JWT role-extraction utility — the canonical, shared form of the
 * per-repo {@code Roles} helper that answers "does this principal hold
 * role X / which domain is it scoped to" in the same way the gateway
 * does.
 *
 * <h2>Responsibility</h2>
 *
 * <p>Provides stateless predicate methods that inspect either a raw
 * {@link Jwt} or the already-converted {@link GrantedAuthority}
 * collection emitted by {@link CasdoorAuthorities}. Earlier per-repo
 * copies were byte-identical; {@code snapdragon-federation-api},
 * {@code snapdragon-admin-bff-api}, {@code snapdragon-user-bff-api}, and
 * {@code snapdragon-owncast-bff-api} all carried the same logic — this
 * class is the single canonical home.
 *
 * <h2>Casdoor roles claim shape</h2>
 *
 * <p>Casdoor's token template can emit the {@code roles} claim in two
 * shapes:
 * <ol>
 *   <li>List of strings: {@code "roles": ["admin", "player"]}</li>
 *   <li>List of role objects (the default):
 *       {@code "roles": [{"name": "admin", ...}, ...]}</li>
 * </ol>
 * Both shapes are handled transparently. Empty or blank entries are
 * skipped so a partially-populated role object never introduces a phantom
 * {@code ROLE_} authority.
 *
 * <h2>Authority-collection overloads</h2>
 *
 * <p>Two distinct input shapes were used across the repos that erase to
 * the same {@code Collection} type at the JVM level, so they are exposed
 * under distinct method names to avoid ambiguous-overload compile errors:
 * <ul>
 *   <li>{@link #isSuperadmin(Collection)} /
 *       {@link #domainOf(Collection)} take
 *       {@code Collection<? extends GrantedAuthority>} — the
 *       user/owncast/admin form emitted by Spring Security.</li>
 *   <li>{@link #isSuperadminNames(Collection)} /
 *       {@link #domainOfNames(Collection)} take the raw authority
 *       {@code Collection<String>} — the federation manifest read path
 *       that passes a {@code Set<String>} of authority strings.</li>
 * </ul>
 *
 * <h2>Consumers</h2>
 *
 * <ul>
 *   <li>{@code snapdragon-admin-bff-api} — admin controller / service
 *       role checks</li>
 *   <li>{@code snapdragon-federation-api} — manifest read path role and
 *       domain checks</li>
 *   <li>{@code snapdragon-user-bff-api} — user BFF role checks</li>
 *   <li>{@code snapdragon-owncast-bff-api} — streaming BFF role checks</li>
 *   <li>{@code snapdragon-forum-bff-api} — forum BFF role checks</li>
 *   <li>{@link CasdoorAuthorities} — MFA freshness check</li>
 *   <li>{@link PrincipalDomain} — SUPERADMIN and domain resolution</li>
 * </ul>
 *
 * @see CasdoorAuthorities
 * @see PrincipalDomain
 * @see DomainRegistry
 * @since snapdragon-commons initial extraction from per-repo copies
 */
public final class Roles {

    // Utility class — no instances.
    private Roles() { }

    // -----------------------------------------------------------------------
    // MFA constants
    // -----------------------------------------------------------------------

    /**
     * The non-role marker authority asserted when the current session
     * completed a second factor recently enough to satisfy the MFA floor
     * (D8 gateway MFA floor, ships dark — off by default).
     *
     * <p>This is NOT a Casdoor role and NOT a permission — it is derived
     * ONLY by {@link #isMfaSatisfied(Jwt, long, long)} from the
     * BFF-written, freshness-validated {@link #MFA_SATISFIED_AT_CLAIM}
     * JWT-Custom claim, and is added to the
     * {@link CasdoorAuthorities#RESERVED_PREFIXES} so a forged
     * {@code permissions:["MFA_SATISFIED"]} can never inject it. It
     * carries no {@code ROLE_} prefix so it can never satisfy a
     * {@code hasRole()} / route-access role check by accident — it is a
     * distinct second-factor proof consumed only by the
     * {@code mfa_required} route gate and privileged step-up operations.
     */
    public static final String MFA_SATISFIED = "MFA_SATISFIED";

    /**
     * The flat top-level JWT-Custom claim the admin-bff stamps on a
     * successful BFF-driven MFA challenge: a numeric epoch-milliseconds
     * timestamp carried as a STRING.
     *
     * <p>Casdoor stores {@code User.properties} as a Go
     * {@code map[string]string} (a JSON number is rejected at write
     * time), so the value persists and is emitted verbatim as a string
     * (e.g. {@code "1750233600000"}). The claim is snake_case and
     * top-level — Casdoor's SnakeToCamel remapping does NOT rewrite the
     * {@code Properties.<key>} branch; this has been empirically pinned
     * in workflow wfza2mi09.
     */
    public static final String MFA_SATISFIED_AT_CLAIM = "mfa_satisfied_at";

    // -----------------------------------------------------------------------
    // MFA freshness check
    // -----------------------------------------------------------------------

    /**
     * Returns {@code true} iff the JWT carries a FRESH MFA stamp that
     * satisfies the configured freshness window.
     *
     * <p>Freshness logic: the {@link #MFA_SATISFIED_AT_CLAIM}
     * epoch-millis string must parse to a positive {@code long}
     * {@code ts} satisfying
     * {@code 0 <= (now - ts) <= freshnessWindowMillis}. Edge cases
     * handled:
     * <ul>
     *   <li>A timestamp in the FUTURE ({@code now - ts < 0}) is REJECTED
     *       — a far-future stamp would otherwise never go stale
     *       (clock-skew / forged-future defense).</li>
     *   <li>A STALE timestamp ({@code now - ts > window}) is
     *       rejected.</li>
     *   <li>A missing, blank, non-numeric, or non-positive value is
     *       rejected.</li>
     * </ul>
     *
     * <p>This method is the SOLE source of the {@link #MFA_SATISFIED}
     * authority; it is never derived from roles or permissions.
     * Fail-closed throughout — never throws, returns {@code false} on
     * every malformed input.
     *
     * <p>{@code now} is passed in by the caller
     * ({@link System#currentTimeMillis()} in production) so the
     * freshness window is deterministically unit-testable.
     *
     * @param jwt                   the validated JWT to inspect; may be
     *                              {@code null} (returns {@code false})
     * @param now                   the current epoch-milliseconds clock
     *                              value, supplied by the caller for
     *                              testability
     * @param freshnessWindowMillis the maximum acceptable age of the MFA
     *                              stamp in milliseconds (e.g.
     *                              {@code 600_000} for 10 minutes)
     * @return {@code true} iff the JWT carries a fresh, valid MFA stamp
     *         within the freshness window
     */
    public static boolean isMfaSatisfied(
            final Jwt jwt,
            final long now,
            final long freshnessWindowMillis) {
        if (jwt == null) {
            return false;
        }
        Long ts = mfaSatisfiedAtMillis(jwt);
        if (ts == null) {
            return false;
        }
        long age = now - ts;
        // Reject timestamps set in the future (forged-future / clock skew).
        if (age < 0) {
            return false;
        }
        // Reject timestamps older than the configured freshness window.
        return age <= freshnessWindowMillis;
    }

    /**
     * Parses the {@link #MFA_SATISFIED_AT_CLAIM} claim from the JWT to
     * its epoch-millis value, or {@code null} when absent, blank,
     * non-numeric, or non-positive.
     *
     * <p>Tolerant of the claim arriving as a {@code String} (the Casdoor
     * JWT-Custom shape) OR as a JSON {@code Number} (defensive — should
     * not happen in practice but parsing it costs nothing). Never throws.
     *
     * @param jwt the validated JWT to read from; never {@code null}
     *            (caller must check)
     * @return the parsed epoch-millis value, or {@code null} for any
     *         invalid input
     */
    private static Long mfaSatisfiedAtMillis(final Jwt jwt) {
        Object raw = jwt.getClaim(MFA_SATISFIED_AT_CLAIM);
        if (raw == null) {
            return null;
        }
        long ts;
        if (raw instanceof Number n) {
            // Defensive: Casdoor writes strings, but handle a JSON number
            // gracefully.
            ts = n.longValue();
        } else {
            String s = raw.toString().trim();
            if (s.isEmpty()) {
                return null;
            }
            try {
                ts = Long.parseLong(s);
            } catch (NumberFormatException e) {
                // Non-numeric claim value — fail closed.
                return null;
            }
        }
        // A non-positive timestamp is never valid (epoch 0 = 1970 = stale).
        return ts > 0 ? ts : null;
    }

    // -----------------------------------------------------------------------
    // Role extraction from JWT
    // -----------------------------------------------------------------------

    /**
     * Returns every role name carried by the JWT's {@code roles} claim,
     * upper-cased and trimmed. Handles both the string-list and
     * role-object shapes emitted by Casdoor. Returns an empty list when
     * the claim is absent or the JWT is {@code null}.
     *
     * @param jwt the validated JWT to read from; may be {@code null}
     * @return a new mutable list of upper-cased role name strings; never
     *         {@code null}
     */
    public static List<String> fromJwt(final Jwt jwt) {
        List<String> out = new ArrayList<>();
        if (jwt == null) {
            return out;
        }
        Object claim = jwt.getClaim("roles");
        if (claim instanceof Collection<?> list) {
            for (Object item : list) {
                String name = roleNameOf(item);
                // Skip blank entries so a partially-populated role object
                // is harmless.
                if (!name.isBlank()) {
                    out.add(name.toUpperCase());
                }
            }
        }
        return out;
    }

    /**
     * Returns {@code true} iff the given role name (case-insensitive) is
     * present in the JWT's {@code roles} claim.
     *
     * @param jwt      the validated JWT to inspect; may be {@code null}
     * @param roleName the role name to look for (case-insensitive,
     *                 trimmed before comparison)
     * @return {@code true} iff the JWT's roles list contains the given
     *         name
     */
    public static boolean has(final Jwt jwt, final String roleName) {
        if (jwt == null || roleName == null) {
            return false;
        }
        String want = roleName.trim().toUpperCase();
        for (String r : fromJwt(jwt)) {
            if (r.equals(want)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns {@code true} iff the JWT's {@code roles} claim or
     * {@code isAdmin} boolean indicates admin authority.
     *
     * <p>Checks both the modern {@code roles: ["admin"]} path and the
     * legacy {@code isAdmin: true} boolean claim (some older Casdoor
     * token templates used the boolean). Both paths are recognised so the
     * transition is backward-compatible.
     *
     * @param jwt the validated JWT to inspect; may be {@code null}
     * @return {@code true} iff the principal holds admin authority
     */
    public static boolean isAdmin(final Jwt jwt) {
        if (jwt == null) {
            return false;
        }
        // Legacy isAdmin boolean claim check — still emitted by some
        // Casdoor templates.
        if (Boolean.TRUE.equals(jwt.getClaim("isAdmin"))) {
            return true;
        }
        return has(jwt, "ADMIN");
    }

    /**
     * Returns {@code true} iff the JWT carries the cross-domain infra
     * super-role.
     *
     * <p>SUPERADMIN is the ONLY role exempt from per-domain scoping: it
     * reaches every surface in every brand (the infra control plane).
     * Both the hyphen spelling ({@code SUPER-ADMIN}) and the underscore
     * spelling ({@code SUPER_ADMIN}) are accepted in addition to the
     * canonical {@code SUPERADMIN}, because Casdoor upper-cases the raw
     * role name without stripping the separator, so a role named
     * {@code super-admin} in Casdoor becomes {@code SUPER-ADMIN} in the
     * JWT.
     *
     * @param jwt the validated JWT to inspect; may be {@code null}
     * @return {@code true} iff the principal holds any recognised
     *         spelling of the super-role
     */
    public static boolean isSuperadmin(final Jwt jwt) {
        return has(jwt, "SUPERADMIN")
                || has(jwt, "SUPER-ADMIN")
                || has(jwt, "SUPER_ADMIN");
    }

    // -----------------------------------------------------------------------
    // Role checks on the already-converted authority collection
    // -----------------------------------------------------------------------

    /**
     * Authority-collection form of {@link #isSuperadmin(Jwt)} for
     * callers that hold the converted Spring {@link GrantedAuthority}
     * objects rather than the raw {@link Jwt}.
     *
     * <p>The {@link CasdoorAuthorities} converter upper-cases the raw
     * Casdoor role name (without stripping its separator) and prepends
     * {@code ROLE_}, so all three spellings of the super-role appear as
     * {@code ROLE_SUPERADMIN}, {@code ROLE_SUPER-ADMIN}, or
     * {@code ROLE_SUPER_ADMIN} in the authority set.
     *
     * <p>This is the form used by the user-bff, owncast-bff, and
     * admin-bff controllers that receive a
     * {@link org.springframework.security.core.Authentication} and
     * extract its authorities via {@code getAuthorities()}.
     *
     * @param authorities the principal's Spring Security authority
     *                    collection; may be {@code null}
     * @return {@code true} iff the authority set contains any recognised
     *         SUPERADMIN authority string
     */
    public static boolean isSuperadmin(
            final Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null) {
            return false;
        }
        for (GrantedAuthority a : authorities) {
            String s = a == null ? null : a.getAuthority();
            if ("ROLE_SUPERADMIN".equals(s)
                    || "ROLE_SUPER-ADMIN".equals(s)
                    || "ROLE_SUPER_ADMIN".equals(s)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Raw-string-collection form of {@link #isSuperadmin(Jwt)} for
     * callers that hold the authority strings directly (e.g. the
     * federation manifest read path that passes a {@code Set<String>} of
     * authority names).
     *
     * <p>Has a distinct method name from
     * {@link #isSuperadmin(Collection)} because {@code Collection<String>}
     * and {@code Collection<? extends GrantedAuthority>} erase to the
     * same JVM type and cannot be distinguished by overload resolution.
     *
     * @param authorities the raw authority string collection; may be
     *                    {@code null}
     * @return {@code true} iff the collection contains any recognised
     *         SUPERADMIN string
     */
    public static boolean isSuperadminNames(
            final Collection<String> authorities) {
        if (authorities == null) {
            return false;
        }
        return authorities.contains("ROLE_SUPERADMIN")
                || authorities.contains("ROLE_SUPER-ADMIN")
                || authorities.contains("ROLE_SUPER_ADMIN");
    }

    /**
     * Returns {@code true} iff the JWT grants the image-builder
     * capability.
     *
     * <p>{@code IMAGE-BUILDER} / {@code IMAGE_BUILDER} is a SEPARATE,
     * explicit capability granted to trusted per-domain admins; it is NOT
     * an automatic admin default. Both separator spellings match (the
     * converter upper-cases the raw Casdoor role name without stripping
     * its separator).
     *
     * @param jwt the validated JWT to inspect; may be {@code null}
     * @return {@code true} iff the principal may build mesh-workload
     *         images
     */
    public static boolean isImageBuilder(final Jwt jwt) {
        return has(jwt, "IMAGE-BUILDER") || has(jwt, "IMAGE_BUILDER");
    }

    // -----------------------------------------------------------------------
    // Domain resolution
    // -----------------------------------------------------------------------

    /**
     * Returns the brand/domain this JWT's principal is scoped to, derived
     * from the cryptographically-validated {@code iss} claim via the
     * {@link DomainRegistry}.
     *
     * <p>Using the issuer — rather than a user-settable claim like
     * {@code owner} or {@code org} — is the security-critical design: a
     * forged claim cannot inject a cross-tenant scope because the issuer
     * is validated by the resource server before any authority is emitted.
     *
     * <p>Returns {@link DomainRegistry#DEFAULT_DOMAIN} when {@code jwt}
     * or {@code registry} is {@code null} (single-issuer fallback).
     * Returns {@code null} when the registry is in multi-brand mode and
     * the issuer is not trusted (the caller must fail closed on a
     * {@code null} domain).
     *
     * @param jwt      the validated JWT; may be {@code null}
     * @param registry the issuer-to-domain registry; may be {@code null}
     * @return the resolved brand/domain string, or {@code null} in
     *         multi-brand mode when the issuer is not trusted
     */
    public static String domainOf(
            final Jwt jwt, final DomainRegistry registry) {
        if (jwt == null || registry == null) {
            return DomainRegistry.DEFAULT_DOMAIN;
        }
        return registry.domainOf(
                jwt.getIssuer() == null
                        ? null : jwt.getIssuer().toString());
    }

    /**
     * Extracts the domain from the already-converted authority collection
     * ({@code DOMAIN_<x>}) — the {@link GrantedAuthority} form used by
     * the user-bff, owncast-bff, and admin-bff.
     *
     * <h3>Fail-closed on ambiguous authority sets</h3>
     *
     * <p>The canonical {@link CasdoorAuthorities} converter stamps
     * EXACTLY ONE issuer-derived {@code DOMAIN_<x>} authority per token.
     * Any other count is anomalous:
     * <ul>
     *   <li>ZERO {@code DOMAIN_} authorities (a hand-built or
     *       pre-converter token) — the tenant cannot be proven; returns
     *       {@code null}.</li>
     *   <li>MORE THAN ONE {@code DOMAIN_} authority — an injection
     *       signature (e.g. a forged
     *       {@code permissions:["DOMAIN_brandy"]} alongside the genuine
     *       issuer {@code DOMAIN_brandx}); returns {@code null} and NEVER
     *       picks one — picking the first would silently grant access to
     *       the wrong brand.</li>
     * </ul>
     *
     * <p>A {@code null} return from this method makes callers' domain-match
     * predicates treat it as a non-match (deny). Prefer
     * {@link #domainOf(Jwt, DomainRegistry)} (issuer-keyed) when a
     * {@link Jwt} is available.
     *
     * @param authorities the principal's Spring Security authority
     *                    collection; may be {@code null}
     * @return the brand/domain string extracted from the single
     *         {@code DOMAIN_<x>} authority, or {@code null} when zero or
     *         more than one are found
     */
    public static String domainOf(
            final Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null) {
            return null;
        }
        String found = null;
        for (GrantedAuthority a : authorities) {
            String s = a == null ? null : a.getAuthority();
            if (s != null && s.startsWith("DOMAIN_")) {
                // More than one DOMAIN_ authority is an injection signature
                // — fail closed.
                if (found != null) {
                    return null;
                }
                found = s.substring("DOMAIN_".length());
            }
        }
        // Returns null (fail-closed) when zero DOMAIN_ authorities found.
        return found;
    }

    /**
     * Raw-string-collection form of {@link #domainOf(Collection)} for
     * callers that hold the authority strings directly rather than
     * {@link GrantedAuthority} objects. Same fail-closed semantics (zero
     * or more than one {@code DOMAIN_} string returns {@code null}). Has
     * a distinct method name because of generic erasure.
     *
     * @param authorities the raw authority string collection; may be
     *                    {@code null}
     * @return the brand/domain string, or {@code null} for zero or
     *         ambiguous results
     */
    public static String domainOfNames(
            final Collection<String> authorities) {
        if (authorities == null) {
            return null;
        }
        String found = null;
        for (String s : authorities) {
            if (s != null && s.startsWith("DOMAIN_")) {
                // More than one DOMAIN_ string is an injection signature —
                // fail closed.
                if (found != null) {
                    return null;
                }
                found = s.substring("DOMAIN_".length());
            }
        }
        return found;
    }

    // -----------------------------------------------------------------------
    // Casdoor identity accessor
    // -----------------------------------------------------------------------

    /**
     * Returns the Casdoor user ID for the JWT principal — the single
     * place we choose between the {@code sub} and {@code id} claims so a
     * Casdoor schema change does not ripple through every controller.
     *
     * <p>Casdoor emits the user ID under {@code sub} in recent token
     * templates and under {@code id} in older ones. This method prefers
     * {@code sub} (non-blank wins) and falls back to {@code id}. Returns
     * {@code null} when neither is present.
     *
     * @param jwt the validated JWT to read from; may be {@code null}
     * @return the Casdoor user ID string, or {@code null} when absent
     */
    public static String casdoorIdOf(final Jwt jwt) {
        if (jwt == null) {
            return null;
        }
        // Prefer the standard `sub` claim; fall back to Casdoor `id`.
        String sub = jwt.getSubject();
        if (sub != null && !sub.isBlank()) {
            return sub;
        }
        Object id = jwt.getClaim("id");
        return id == null ? null : id.toString();
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Extracts the role name string from a roles-claim entry, handling
     * both the plain string shape ({@code "admin"}) and the role-object
     * shape ({@code {"name": "admin", ...}}).
     *
     * @param item one element from the JWT {@code roles} claim list; may
     *             be {@code null}
     * @return the trimmed role name string, or {@code ""} for
     *         unrecognised shapes
     */
    private static String roleNameOf(final Object item) {
        if (item == null) {
            return "";
        }
        if (item instanceof String s) {
            return s.trim();
        }
        if (item instanceof Map<?, ?> m) {
            // Role-object shape: {"name": "admin", ...}
            Object name = m.get("name");
            if (name instanceof String s && !s.isBlank()) {
                return s.trim();
            }
        }
        return "";
    }
}

package systems.snapdragon.commons.security;

import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Per-request tenant scope resolved once at the controller boundary — a
 * value object that pairs a principal's brand/domain with its SUPERADMIN
 * flag and is threaded into the service and repository layers to scope
 * every read and write.
 *
 * <h2>Responsibility</h2>
 *
 * <p>Both the domain predicate ({@code WHERE domain = :domain}) and the
 * SUPERADMIN bypass (omit predicate, see all brands) are derived ONCE
 * from the cryptographically validated {@link Jwt} at the controller
 * entry point and forwarded as a single typed value object rather than
 * re-computing them from the raw token on every downstream call.
 *
 * <p>This is the canonical, shared form of the instance-based
 * {@code DomainScope} class that {@code snapdragon-federation-api} and
 * {@code snapdragon-admin-bff-api} each carried. The class was renamed
 * {@code PrincipalDomain} here so the name {@code DomainScope} could be
 * freed for the minimal SQL-predicate static utility used by the
 * user/owncast repos — see
 * {@link systems.snapdragon.commons.tenancy.DomainScope}.
 *
 * <h2>Two security-derived fields</h2>
 *
 * <p>Both are derived exclusively from the CRYPTOGRAPHICALLY-VALIDATED
 * token, never from a user-settable claim:
 *
 * <pre>
 *  Field         | Source                              | Effect
 *  ──────────────┼─────────────────────────────────────┼──────────────
 *  domain()      | validated {@code iss} via registry  | WHERE domain =
 *                | (single-issuer: always "default")   | :domain
 *  superadmin()  | {@code roles} claim only, via       | predicate
 *                | {@link Roles#isSuperadmin(Jwt)}     | omitted
 * </pre>
 *
 * <h2>Fail-closed sentinel</h2>
 *
 * <p>A {@code null} or blank domain (unknown issuer in multi-brand mode
 * — which the resource server would already have rejected with
 * {@code 401}) collapses to the {@link #NO_DOMAIN} sentinel. A query
 * predicated on {@link #NO_DOMAIN} matches no real brand's rows, so a
 * token that somehow reaches the service layer without a resolvable
 * tenant sees nothing rather than another brand's data.
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <pre>
 *  Principal             | domain()            | superadmin() | scoped()
 *  ──────────────────────┼─────────────────────┼──────────────┼─────────
 *  ROLE_USER / ROLE_MOD  | issuer-derived brand| false        | true
 *  ROLE_ADMIN            | issuer-derived brand| false        | true
 *  ROLE_SUPERADMIN       | home brand (writes) | true         | false
 *  Internal effector     | explicit brand      | true         | false
 *  Unresolvable token    | NO_DOMAIN sentinel  | false        | true
 * </pre>
 *
 * <h2>Consumers</h2>
 *
 * <ul>
 *   <li>{@code snapdragon-admin-bff-api} — all admin CRUD scoped by
 *       domain</li>
 *   <li>{@code snapdragon-federation-api} — manifest render domain
 *       pinning</li>
 *   <li>{@code snapdragon-user-bff} — user-profile / preferences
 *       scoping</li>
 *   <li>{@code snapdragon-owncast-bff} — streaming metadata scoping</li>
 *   <li>{@code snapdragon-forum-bff} — forum moderation scoping</li>
 * </ul>
 *
 * @see DomainRegistry
 * @see Roles
 * @see systems.snapdragon.commons.tenancy.DomainScope
 * @since snapdragon-commons initial extraction from per-repo copies
 */
public final class PrincipalDomain {

    /**
     * The fail-closed sentinel domain assigned when the principal's tenant
     * cannot be resolved (e.g. an unknown issuer in multi-brand mode). The
     * leading space character can never equal a
     * {@link DomainRegistry}-sanitized domain name, which is restricted to
     * {@code [a-z0-9-]}, so a query predicated on this value always
     * returns zero rows.
     */
    public static final String NO_DOMAIN = " no-domain";

    /** The resolved brand/domain for this principal; never {@code null}. */
    @NonNull
    private final String domain;

    /** Whether this principal holds the infra super-role (unscoped). */
    private final boolean superadmin;

    private PrincipalDomain(
            @NonNull final String resolvedDomain,
            final boolean isSuperadmin) {
        this.domain = resolvedDomain;
        this.superadmin = isSuperadmin;
    }

    // -----------------------------------------------------------------------
    // Factory methods
    // -----------------------------------------------------------------------

    /**
     * Resolves the tenant scope from a Spring {@link Authentication}.
     *
     * <p>SUPERADMIN (roles claim via {@link Roles#isSuperadmin(Jwt)}) is
     * unscoped; otherwise the domain is derived from the validated issuer
     * via the registry. Anything that is not a JWT-backed authentication,
     * or a JWT whose issuer cannot be resolved, collapses to the
     * fail-closed {@link #NO_DOMAIN} sentinel with
     * {@code superadmin = false}.
     *
     * @param auth     the Spring Security authentication for the current
     *                 request; may be {@code null} (treated as
     *                 unresolvable)
     * @param registry the issuer-to-domain registry used to resolve the
     *                 domain from the token's {@code iss} claim
     * @return the resolved {@link PrincipalDomain}; never {@code null}
     */
    public static PrincipalDomain of(
            final Authentication auth, final DomainRegistry registry) {
        // Non-JWT authentication (e.g. anonymous, API-key) cannot carry a
        // tenant.
        if (auth == null || !(auth.getPrincipal() instanceof Jwt jwt)) {
            return new PrincipalDomain(NO_DOMAIN, false);
        }
        return resolve(jwt, registry);
    }

    /**
     * Resolves the tenant scope directly from a {@link Jwt}.
     *
     * <p>SUPERADMIN is unscoped (but still carries a home domain for the
     * rows it writes); any other principal is pinned to its
     * issuer-derived domain. A {@code null} JWT or an unresolvable issuer
     * fails closed to {@link #NO_DOMAIN}.
     *
     * @param jwt      the validated JWT from the current request; may be
     *                 {@code null}
     * @param registry the issuer-to-domain registry
     * @return the resolved {@link PrincipalDomain}; never {@code null}
     */
    public static PrincipalDomain resolve(
            final Jwt jwt, final DomainRegistry registry) {
        if (jwt == null) {
            // No token — fail closed: no domain, not superadmin.
            return new PrincipalDomain(NO_DOMAIN, false);
        }
        // Both SUPERADMIN and regular principals carry the home domain
        // (used for writes). Only SUPERADMIN has the unscoped flag set.
        boolean sa = Roles.isSuperadmin(jwt);
        return new PrincipalDomain(
                safe(Roles.domainOf(jwt, registry)), sa);
    }

    /**
     * Creates a scoped (non-superadmin) {@link PrincipalDomain} for an
     * explicit domain name, intended for tests and internal callers that
     * already know their domain without needing to resolve it from a JWT.
     *
     * @param domain the brand/domain name; {@code null} or blank collapses
     *               to {@link #NO_DOMAIN}
     * @return a scoped {@link PrincipalDomain} for the given domain
     */
    public static PrincipalDomain forDomain(final String domain) {
        return new PrincipalDomain(safe(domain), false);
    }

    /**
     * Creates an UNSCOPED (superadmin) {@link PrincipalDomain} homed at
     * the given domain — the infra control-plane scope an internal SYSTEM
     * effector acts under (e.g. an App-Store {@code AddServiceEffector}
     * that already knows the target brand and must read/mutate that
     * brand's rows without holding a user JWT).
     *
     * <p>Behaves identically to a SUPERADMIN principal on reads/mutations
     * (omits the domain predicate), but {@code domain} is recorded as the
     * home brand on any rows it writes. NOT derived from a token — only
     * for trusted internal callers.
     *
     * @param domain the brand/domain to home this effector to;
     *               {@code null} or blank collapses to {@link #NO_DOMAIN}
     * @return an unscoped {@link PrincipalDomain} with
     *         {@code superadmin = true}
     */
    public static PrincipalDomain superadminFor(final String domain) {
        return new PrincipalDomain(safe(domain), true);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /**
     * The brand this principal belongs to, used both as the
     * {@code WHERE domain = :domain} predicate for scoped reads/mutations
     * and as the value stamped on rows the principal writes. Never
     * {@code null} — collapses to {@link #NO_DOMAIN} when the tenant
     * cannot be resolved.
     *
     * @return the resolved brand/domain string; never {@code null}
     */
    @NonNull
    public String domain() {
        return domain;
    }

    /**
     * Returns {@code true} iff this principal holds the infra super-role
     * — that is, UNSCOPED access across all brands (the infra control
     * plane).
     *
     * <p>When {@code true}, the service / repository layer omits the
     * domain predicate and the principal sees / mutates every brand's
     * rows.
     *
     * @return {@code true} iff this is a SUPERADMIN (unscoped) principal
     */
    public boolean superadmin() {
        return superadmin;
    }

    /**
     * Returns {@code true} iff a per-row domain predicate should be
     * applied — that is, when this principal is NOT SUPERADMIN.
     *
     * <p>Convenience inverse of {@link #superadmin()} for use in service
     * / repository layer {@code if (scope.scoped()) { ... }} checks.
     *
     * @return {@code true} iff the principal is scoped to a specific brand
     */
    public boolean scoped() {
        return !superadmin;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Guards against null or blank domain values by substituting the
     * fail-closed {@link #NO_DOMAIN} sentinel. Called before every
     * constructor invocation so the {@code @NonNull domain} field is
     * always a safe, non-null value.
     *
     * @param domain the raw domain string to check
     * @return {@code domain} when non-null and non-blank, otherwise
     *         {@link #NO_DOMAIN}
     */
    @NonNull
    private static String safe(final String domain) {
        return (domain == null || domain.isBlank()) ? NO_DOMAIN : domain;
    }
}

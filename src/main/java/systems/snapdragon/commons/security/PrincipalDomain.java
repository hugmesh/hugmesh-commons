package systems.snapdragon.commons.security;

import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The per-request TENANT SCOPE a principal acts under — an instance-based value
 * object resolved ONCE at the controller boundary from the {@link Authentication} (or
 * the raw {@link Jwt}) and threaded into the service / repository layer so every
 * query/mutation is scoped to the principal's own brand.
 *
 * <p>Canonical, shared form of the instance-based {@code DomainScope} that federation
 * and admin-bff each carried (renamed {@code PrincipalDomain} to free the name
 * {@code DomainScope} for the minimal static SQL-predicate utility used by the
 * user/owncast repos — see {@code systems.snapdragon.commons.tenancy.DomainScope}).
 *
 * <p>Two factors, both derived from the CRYPTOGRAPHICALLY-VALIDATED token (never a
 * user-settable claim):
 * <ul>
 *   <li>{@link #domain()} — the brand the principal belongs to, from the validated
 *       {@code iss} via {@link DomainRegistry} ({@code "default"} on single-issuer
 *       clusters). Used as the row predicate {@code WHERE domain = :domain} for a
 *       scoped principal AND stamped on every row it writes.</li>
 *   <li>{@link #superadmin()} — whether the principal holds the infra super-role
 *       (from the {@code roles} claim only, via {@link Roles#isSuperadmin(Jwt)}).
 *       SUPERADMIN is UNSCOPED: it reads/mutates every brand's rows (the infra
 *       control plane), so the predicate is omitted.</li>
 * </ul>
 *
 * <p><b>Fail-closed.</b> A null/blank domain (an unknown issuer in multi-brand mode,
 * which the resource server would already have 401'd) collapses to a sentinel that
 * matches NO real brand's rows, so a token that somehow reaches here with no resolvable
 * tenant sees nothing rather than another brand's data.
 */
public final class PrincipalDomain {

    /** A domain value that intentionally matches no real brand row — the fail-closed
     *  sentinel for a scoped principal whose tenant could not be resolved. The leading
     *  space can never equal a {@link DomainRegistry} sanitized domain (lower-alnum +
     *  hyphen only). */
    public static final String NO_DOMAIN = " no-domain";

    private final @NonNull String domain;
    private final boolean superadmin;

    private PrincipalDomain(@NonNull String domain, boolean superadmin) {
        this.domain = domain;
        this.superadmin = superadmin;
    }

    /**
     * Resolve the scope from a Spring {@link Authentication}. SUPERADMIN (roles claim)
     * is unscoped; otherwise the domain comes from the validated issuer via the
     * registry. Anything that is not a JWT authentication (or a JWT with no resolvable
     * tenant) collapses to the fail-closed {@link #NO_DOMAIN} sentinel (and never
     * superadmin).
     */
    public static PrincipalDomain of(Authentication auth, DomainRegistry registry) {
        if (auth == null || !(auth.getPrincipal() instanceof Jwt jwt)) {
            return new PrincipalDomain(NO_DOMAIN, false);
        }
        return resolve(jwt, registry);
    }

    /**
     * Resolve the scope directly from a {@link Jwt}. SUPERADMIN is unscoped (but still
     * carries a home domain for the rows it writes); otherwise the principal is pinned
     * to its issuer-derived domain. An unresolvable issuer fails closed
     * ({@link #NO_DOMAIN}).
     */
    public static PrincipalDomain resolve(Jwt jwt, DomainRegistry registry) {
        if (jwt == null) {
            return new PrincipalDomain(NO_DOMAIN, false);
        }
        if (Roles.isSuperadmin(jwt)) {
            return new PrincipalDomain(safe(Roles.domainOf(jwt, registry)), true);
        }
        return new PrincipalDomain(safe(Roles.domainOf(jwt, registry)), false);
    }

    /** A per-domain scope for an explicit domain (test / internal use). Never
     *  superadmin. */
    public static PrincipalDomain forDomain(String domain) {
        return new PrincipalDomain(safe(domain), false);
    }

    /**
     * An UNSCOPED (superadmin) scope homed at {@code domain} — the infra control-plane
     * scope an internal SYSTEM effector acts under (e.g. an App-Store
     * {@code AddServiceEffector}, which already knows the explicit target brand and must
     * read/mutate that brand's route-access rows). It is unscoped on reads/mutations
     * exactly like a SUPERADMIN principal, with {@code domain} as its home brand for any
     * row it writes. NOT derived from a token — only for trusted internal callers.
     */
    public static PrincipalDomain superadminFor(String domain) {
        return new PrincipalDomain(safe(domain), true);
    }

    @NonNull
    private static String safe(String domain) {
        return (domain == null || domain.isBlank()) ? NO_DOMAIN : domain;
    }

    /** The brand this principal belongs to (used both as the read predicate for a
     *  scoped principal and as the value stamped on rows it writes). Never null —
     *  collapses to {@link #NO_DOMAIN} when the tenant cannot be resolved. */
    @NonNull
    public String domain() {
        return domain;
    }

    /** True iff this principal is the infra super-role (UNSCOPED — sees/mutates all
     *  brands). */
    public boolean superadmin() {
        return superadmin;
    }

    /** True iff a per-row domain predicate should be applied (i.e. NOT superadmin).
     *  Superadmin omits the predicate and sees every brand's rows. */
    public boolean scoped() {
        return !superadmin;
    }
}

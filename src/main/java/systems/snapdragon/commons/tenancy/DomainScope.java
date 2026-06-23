package systems.snapdragon.commons.tenancy;

/**
 * SQL-predicate utility for the {@code domain = :domain} tenant-isolation
 * clause appended by every per-domain repository.
 *
 * <h2>Responsibility</h2>
 *
 * <p>This is the data-layer half of the multi-brand isolation boundary.
 * Every query that reads or mutates brand-specific rows appends
 * {@link #andPredicate(String)} to its SQL so that a scoped principal
 * only ever touches rows that belong to its own brand. The SUPERADMIN
 * cross-domain bypass is expressed by passing {@code null} as the domain
 * — {@code andPredicate} then returns an empty string, meaning no
 * predicate is added and the query spans all brands.
 *
 * <p>This is the canonical, shared form of the minimal static utility the
 * user-bff, owncast-bff, and forum-bff repos each carried (owncast added
 * {@link #andPredicate(String)}; this class unifies all variants).
 *
 * <p>For the instance-based, controller-boundary tenant scope — the value
 * object resolved from an
 * {@link org.springframework.security.core.Authentication} at the
 * controller entry point (SUPERADMIN-aware, carries the domain as a
 * field) — see
 * {@link systems.snapdragon.commons.security.PrincipalDomain}.
 *
 * <h2>Convention</h2>
 *
 * <p>The service / controller layer resolves the principal's domain from
 * the validated token issuer and passes it down as a plain
 * {@code String}:
 *
 * <pre>
 *  domain value  | SQL effect                         | who passes it
 *  ──────────────┼────────────────────────────────────┼──────────────────
 *  non-null/blank| {@code AND domain = :domain}       | scoped principal
 *  null or blank | no predicate — full cross-domain   | SUPERADMIN only
 * </pre>
 *
 * <p>The domain predicate is ALWAYS an ADDITIONAL restriction alongside
 * any existing ownership clause (e.g. {@code author_subject = :subject}).
 * It never replaces or weakens per-row owner tracking.
 *
 * <h2>Consumers</h2>
 *
 * <p>Used in raw-SQL repository methods in:
 * <ul>
 *   <li>{@code snapdragon-user-bff} — user-profile / preferences
 *       queries</li>
 *   <li>{@code snapdragon-owncast-bff} — streaming metadata queries</li>
 *   <li>{@code snapdragon-forum-bff} — forum-post / moderation
 *       queries</li>
 * </ul>
 *
 * @see systems.snapdragon.commons.security.PrincipalDomain
 * @see systems.snapdragon.commons.security.DomainRegistry
 * @since snapdragon-commons initial extraction from per-repo copies
 */
public final class DomainScope {

    // Utility class — no instances.
    private DomainScope() { }

    /**
     * The named bind parameter used in the domain predicate SQL fragment.
     * Repository code binds the resolved domain string under this name:
     * {@code statement.bind(DomainScope.PARAM, domain)}.
     */
    public static final String PARAM = "domain";

    /**
     * Returns the SQL fragment to splice into a {@code WHERE} clause for
     * the given domain.
     *
     * <ul>
     *   <li>When {@code domain} is non-null and non-blank (a scoped
     *       principal): returns {@code " AND domain = :domain"} — the
     *       query is restricted to exactly that brand's rows. The caller
     *       must bind {@link #PARAM} to the domain value.</li>
     *   <li>When {@code domain} is {@code null} or blank (a SUPERADMIN
     *       bypass): returns the empty string — no predicate is added and
     *       the query spans every brand. Only a SUPERADMIN principal
     *       should pass {@code null} here; a scoped caller is always
     *       given its concrete domain by the service layer.</li>
     * </ul>
     *
     * @param domain the resolved brand/domain from the principal, or
     *               {@code null} to indicate a SUPERADMIN cross-domain
     *               bypass
     * @return {@code " AND domain = :domain"} for scoped principals, or
     *         {@code ""} for the SUPERADMIN cross-domain bypass
     */
    public static String andPredicate(final String domain) {
        // Null or blank domain means the caller is SUPERADMIN (unscoped):
        // omit the predicate so the query spans all brands.
        return isUnscoped(domain) ? "" : " AND domain = :" + PARAM;
    }

    /**
     * Returns {@code true} when the given domain represents the SUPERADMIN
     * cross-domain bypass — that is, when no {@code domain} predicate
     * should be added to the query.
     *
     * <p>A {@code null} or blank domain is the signal that the caller is
     * unscoped (SUPERADMIN). A concrete brand string (e.g.
     * {@code "default"}, {@code "brandy"}) is always scoped.
     *
     * @param domain the domain value to test
     * @return {@code true} iff {@code domain} is {@code null} or blank
     */
    public static boolean isUnscoped(final String domain) {
        return domain == null || domain.isBlank();
    }
}

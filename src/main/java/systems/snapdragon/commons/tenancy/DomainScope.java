package systems.snapdragon.commons.tenancy;

/**
 * The optional {@code domain = :domain} predicate every per-domain repository appends
 * to scope a read/mutation to the caller's tenant — the data-layer half of the
 * multi-brand isolation boundary. Canonical, shared form of the minimal static
 * utility the user-bff / owncast-bff (and forum-bff) repos carried (owncast added the
 * {@link #andPredicate(String)} SQL-fragment helper).
 *
 * <p>For the instance-based, controller-boundary tenant scope (SUPERADMIN-aware value
 * object resolved from the {@code Authentication}), see
 * {@code systems.snapdragon.commons.security.PrincipalDomain}.
 *
 * <p><b>Convention.</b> The service/controller layer resolves the principal's domain
 * from the validated token issuer and passes it down:
 * <ul>
 *   <li>a NON-null {@code domain} ⇒ the SQL gains {@code AND domain = :domain} and
 *       binds it, so the caller only ever touches rows in their OWN brand;</li>
 *   <li>a {@code null} / blank {@code domain} ⇒ NO predicate is added — this is the
 *       SUPERADMIN (cross-domain infra super-role) bypass: SUPERADMIN sees/mutates
 *       every brand's rows. The caller decides this (it passes {@code null} only for a
 *       SUPERADMIN principal); a non-SUPERADMIN caller is ALWAYS passed its concrete
 *       domain.</li>
 * </ul>
 *
 * <p>Domain is ALWAYS an ADDITIONAL predicate alongside any existing owner/author one
 * — it never replaces or weakens owner-tracking (author_subject == JWT subject). A
 * scoped ADMIN of brand X sees ONLY brand X's rows.
 */
public final class DomainScope {

    private DomainScope() {}

    /** The named bind parameter for the domain predicate. */
    public static final String PARAM = "domain";

    /**
     * The SQL fragment to splice into a WHERE clause for the given domain:
     * {@code " AND domain = :domain"} when {@code domain} is non-null/blank, else the
     * empty string (SUPERADMIN cross-domain bypass — no predicate).
     */
    public static String andPredicate(String domain) {
        return isUnscoped(domain) ? "" : " AND domain = :" + PARAM;
    }

    /** True iff the domain represents the SUPERADMIN cross-domain bypass (null/blank
     *  ⇒ no predicate). */
    public static boolean isUnscoped(String domain) {
        return domain == null || domain.isBlank();
    }
}

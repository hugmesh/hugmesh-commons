package systems.hugmesh.commons.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Single source of truth for the Casdoor JWT-to-Spring-authorities
 * mapping used by every reactive BFF's resource-server security
 * configuration.
 *
 * <h2>Responsibility</h2>
 *
 * <p>Produces the {@link GrantedAuthority} list that Spring Security
 * attaches to the authenticated principal from three claim sources (see
 * below). Earlier per-repo copies were logic-byte-identical, differing
 * only in access modifiers and copy-paste drift; this class is the
 * canonical form so every BFF's single-issuer {@code SecurityConfig} and
 * the optional multi-issuer {@link TenancyResourceServerConfig} decoder
 * paths emit BYTE-IDENTICAL authorities.
 *
 * <h2>Three claim sources</h2>
 *
 * <pre>
 *  Priority | Claim               | Authority emitted
 *  ─────────┼─────────────────────┼────────────────────────────────────
 *  1        | {@code roles} array | {@code ROLE_<UPPER>} per entry
 *           |                     | (string or object with name field)
 *  2        | {@code permissions} | verbatim — UNLESS it starts with a
 *           | array               | RESERVED prefix
 *           |                     | (see {@link #RESERVED_PREFIXES})
 *  3        | {@code isAdmin}     | {@code ROLE_ADMIN} (legacy boolean)
 *           | boolean             |
 *  always   | validated iss       | {@code DOMAIN_<x>} — exactly one
 *  D8 opt-in| mfa_satisfied_at   | {@code MFA_SATISFIED} (when fresh)
 * </pre>
 *
 * <p>Every authenticated principal floors to {@code ROLE_USER} and
 * receives exactly one issuer-derived {@code DOMAIN_<x>} authority.
 *
 * <h2>Authority-injection defense</h2>
 *
 * <p>A {@code permissions} entry that starts with a RESERVED prefix
 * ({@code ROLE_}, {@code DOMAIN_}, or {@code MFA_SATISFIED}) is DROPPED.
 * Without this guard, a token carrying
 * {@code permissions:["DOMAIN_brandy"]} could forge a cross-tenant scope,
 * and {@code permissions:["ROLE_SUPERADMIN"]} could forge the super-role.
 * See {@link #RESERVED_PREFIXES}.
 *
 * <h2>Consumers</h2>
 *
 * <ul>
 *   <li>{@code hugmesh-admin-bff-api} {@code SecurityConfig}
 *       (single-issuer path)</li>
 *   <li>{@code hugmesh-federation-api} {@code SecurityConfig}
 *       (single-issuer path)</li>
 *   <li>{@code hugmesh-user-bff-api} {@code SecurityConfig}
 *       (single-issuer path)</li>
 *   <li>{@code hugmesh-owncast-bff-api} {@code SecurityConfig}
 *       (single-issuer path)</li>
 *   <li>{@code hugmesh-forum-bff-api} {@code SecurityConfig}
 *       (single-issuer path)</li>
 *   <li>{@link TenancyResourceServerConfig} (multi-issuer path — same
 *       converter)</li>
 * </ul>
 *
 * @see DomainRegistry
 * @see Roles
 * @see TenancyResourceServerConfig
 * @since hugmesh-commons initial extraction from per-repo copies
 */
public final class CasdoorAuthorities {

    // Utility class — no instances.
    private CasdoorAuthorities() { }

    // -----------------------------------------------------------------------
    // MFA configuration record
    // -----------------------------------------------------------------------

    /**
     * Configuration carrier for the D8 gateway MFA floor derivation.
     *
     * <p>Carried as a value object so the single-issuer
     * ({@code SecurityConfig}) and multi-issuer
     * ({@link TenancyResourceServerConfig}) paths derive the
     * {@code MFA_SATISFIED} marker BYTE-IDENTICALLY, using the same
     * {@code app.mfa.enabled} and {@code app.mfa.freshness-window}
     * values.
     *
     * <p>Ships DARK: when {@code enabled} is {@code false} (the default),
     * the converter emits the legacy authority set verbatim and
     * {@code MFA_SATISFIED} is NEVER produced. Flipping {@code enabled}
     * to {@code true} activates freshness checking against the
     * BFF-written {@link Roles#MFA_SATISFIED_AT_CLAIM} claim.
     *
     * @param enabled               whether the {@code MFA_SATISFIED}
     *                              marker is derived at all;
     *                              {@code false} = legacy authority set
     *                              (dark default)
     * @param freshnessWindowMillis the maximum accepted age of the
     *                              {@code mfa_satisfied_at} stamp —
     *                              {@code 0 <= (now - ts) <= window};
     *                              typically {@code 600_000} (10 minutes)
     */
    public record MfaConfig(boolean enabled, long freshnessWindowMillis) {

        /**
         * The dark default — MFA derivation OFF, byte-identical to the
         * legacy authority set that existed before the D8 MFA floor was
         * introduced.
         */
        public static final MfaConfig DISABLED =
                new MfaConfig(false, 0L);
    }

    // -----------------------------------------------------------------------
    // Authority-injection defense
    // -----------------------------------------------------------------------

    /**
     * Authority-string prefixes RESERVED for the converter's own
     * controlled logic — never allowed to originate from a
     * user-influenced {@code permissions} claim entry.
     *
     * <ul>
     *   <li><b>{@code ROLE_}</b> — emitted ONLY from the {@code roles}
     *       claim (each role name upper-cased and prefixed) and from the
     *       legacy {@code isAdmin} boolean. A verbatim
     *       {@code permissions} entry must never become a {@code ROLE_*}
     *       authority because doing so would let a user-supplied
     *       permission string forge any Spring Security role.</li>
     *   <li><b>{@code DOMAIN_}</b> — emitted ONLY from the
     *       cryptographically-validated {@code iss} (exactly one per
     *       token). A verbatim {@code permissions} entry must never forge
     *       a {@code DOMAIN_*} tenant scope or a token from brand-X
     *       could escalate into brand-Y. Note that a {@code roles} entry
     *       CAN contain the string {@code "DOMAIN_x"}, but the converter
     *       always prepends {@code ROLE_} first, producing the inert
     *       authority {@code ROLE_DOMAIN_X} — not a tenant scope.</li>
     *   <li><b>{@code MFA_SATISFIED}</b> (D8) — the second-factor
     *       marker, emitted ONLY from the BFF-written,
     *       freshness-validated {@link Roles#MFA_SATISFIED_AT_CLAIM}
     *       claim. A forged {@code permissions:["MFA_SATISFIED"]} must
     *       be dropped so a step-up gate cannot be satisfied without an
     *       actual recent MFA event. Listed as a full prefix rather than
     *       an exact match so any casing / whitespace variant is caught
     *       by the same trim-and-upper guard.</li>
     * </ul>
     *
     * <p>Security: without this filter a brand-X token carrying
     * {@code permissions:["DOMAIN_brandy"]} or
     * {@code permissions:["ROLE_SUPERADMIN"]} would inject a forged
     * tenant scope / super-role and escalate cross-domain. A
     * {@code permissions:["MFA_SATISFIED"]} would forge a second factor.
     */
    static final String[] RESERVED_PREFIXES =
            {"ROLE_", "DOMAIN_", "MFA_SATISFIED"};

    /**
     * Returns {@code true} iff the given authority string starts with a
     * RESERVED prefix and must therefore be dropped from the
     * {@code permissions} claim.
     *
     * @param authority the authority string to test (trimmed, upper-cased
     *                  before check)
     * @return {@code true} iff the string starts with any of the
     *         {@link #RESERVED_PREFIXES}
     */
    private static boolean isReserved(final String authority) {
        String upper = authority.trim().toUpperCase();
        for (String prefix : RESERVED_PREFIXES) {
            if (upper.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Converter factories
    // -----------------------------------------------------------------------

    /**
     * Builds a {@link Converter} from {@link Jwt} to a reactive
     * {@link Flux} of {@link GrantedAuthority} objects, bound to the
     * given {@link DomainRegistry}.
     *
     * <p>MFA derivation is OFF ({@link MfaConfig#DISABLED}) — the
     * emitted authority set is byte-identical to the legacy set that
     * existed before the D8 MFA floor. Use this overload when the repo
     * has not yet opted into MFA checks.
     *
     * @param domainRegistry the issuer-to-domain registry used to resolve
     *                       the {@code DOMAIN_<x>} authority; may be
     *                       {@code null} (maps all issuers to
     *                       {@code "default"})
     * @return a converter that, for each validated JWT, emits the
     *         HugMesh authority set as a {@link Flux}
     */
    public static Converter<Jwt, Flux<GrantedAuthority>> converter(
            final DomainRegistry domainRegistry) {
        return converter(domainRegistry, MfaConfig.DISABLED);
    }

    /**
     * Builds a {@link Converter} from {@link Jwt} to a reactive
     * {@link Flux} of {@link GrantedAuthority} objects, bound to the
     * given {@link DomainRegistry} and {@link MfaConfig}.
     *
     * <p>When {@code mfa.enabled()} is {@code false} (the dark default)
     * the emitted authorities are byte-identical to the legacy set. When
     * {@code true}, a FRESH BFF-written
     * {@link Roles#MFA_SATISFIED_AT_CLAIM} claim adds the
     * {@link Roles#MFA_SATISFIED} marker. Production clock is
     * {@link System#currentTimeMillis()}.
     *
     * @param domainRegistry the issuer-to-domain registry; may be
     *                       {@code null}
     * @param mfa            the MFA derivation configuration; must not be
     *                       {@code null}
     * @return a converter emitting the HugMesh authority set as a
     *         {@link Flux}
     */
    public static Converter<Jwt, Flux<GrantedAuthority>> converter(
            final DomainRegistry domainRegistry, final MfaConfig mfa) {
        // Wrap the pure mapping in a Flux so it fits the
        // ReactiveJwtAuthenticationConverter API.
        return jwt -> Flux.fromIterable(
                authorities(jwt, domainRegistry, mfa,
                        System.currentTimeMillis()));
    }

    // -----------------------------------------------------------------------
    // Pure mapping (also exposed for unit testing)
    // -----------------------------------------------------------------------

    /**
     * Computes the authority list for a validated JWT without MFA
     * derivation — the legacy authority set.
     *
     * <p>Exposed as a public method (not just via the converter) so it
     * can be called directly in unit tests that want a plain {@code List}
     * rather than a {@link Flux}.
     *
     * @param jwt            the validated JWT to map; must not be
     *                       {@code null}
     * @param domainRegistry the issuer-to-domain registry; may be
     *                       {@code null}
     * @return a new mutable list of {@link GrantedAuthority} objects
     */
    public static List<GrantedAuthority> authorities(
            final Jwt jwt, final DomainRegistry domainRegistry) {
        return authorities(jwt, domainRegistry, MfaConfig.DISABLED,
                System.currentTimeMillis());
    }

    /**
     * Computes the authority list for a validated JWT with explicit
     * {@link MfaConfig} and a caller-supplied {@code now} epoch-millis
     * clock, enabling deterministic unit tests of the MFA freshness
     * window.
     *
     * <p>Mapping steps, in order:
     * <ol>
     *   <li>Add {@code ROLE_USER} as the floor authority — every
     *       authenticated principal holds this.</li>
     *   <li>Map the {@code roles} claim entries to
     *       {@code ROLE_<UPPER>} authorities (string or object shape,
     *       both handled).</li>
     *   <li>Map the {@code permissions} claim entries verbatim — but
     *       DROP any entry whose upper-cased form starts with a
     *       {@link #RESERVED_PREFIXES} prefix
     *       (authority-injection defense).</li>
     *   <li>Add {@code ROLE_ADMIN} from the legacy
     *       {@code isAdmin: true} boolean claim if present.</li>
     *   <li>Optionally add {@link Roles#MFA_SATISFIED} when MFA is
     *       enabled and the {@link Roles#MFA_SATISFIED_AT_CLAIM} claim
     *       is fresh.</li>
     *   <li>Add exactly one {@code DOMAIN_<x>} authority derived from
     *       the cryptographically-validated {@code iss} claim via the
     *       registry. A null domain (unknown issuer in multi-brand mode)
     *       maps to {@code "default"} rather than emitting
     *       {@code "DOMAIN_null"}.</li>
     * </ol>
     *
     * @param jwt            the validated JWT to map; must not be
     *                       {@code null}
     * @param domainRegistry the issuer-to-domain registry; may be
     *                       {@code null}
     * @param mfa            the MFA derivation configuration; must not be
     *                       {@code null}
     * @param now            current epoch-milliseconds for the MFA
     *                       freshness check; use
     *                       {@link System#currentTimeMillis()} in
     *                       production
     * @return a new mutable list of {@link GrantedAuthority} objects
     */
    public static List<GrantedAuthority> authorities(
            final Jwt jwt,
            final DomainRegistry domainRegistry,
            final MfaConfig mfa,
            final long now) {
        var auths = new ArrayList<GrantedAuthority>();

        // 1. Floor authority: every authenticated principal holds
        // ROLE_USER.
        auths.add(new SimpleGrantedAuthority("ROLE_USER"));

        // 2. Map the roles claim to ROLE_<UPPER> authorities.
        Object rolesClaim = jwt.getClaim("roles");
        if (rolesClaim instanceof Collection<?> list) {
            for (Object r : list) {
                String name = roleNameOf(r);
                if (!name.isBlank()) {
                    // Prefix forces ROLE_ on every roles-claim entry. This
                    // means a roles entry of "DOMAIN_x" becomes
                    // "ROLE_DOMAIN_X" — an inert authority that cannot
                    // satisfy a tenant-scope check (see RESERVED_PREFIXES).
                    auths.add(new SimpleGrantedAuthority(
                            "ROLE_" + name.trim().toUpperCase()));
                }
            }
        }

        // 3. Map the permissions claim verbatim, dropping reserved-prefix
        // entries.
        Object permsClaim = jwt.getClaim("permissions");
        if (permsClaim instanceof Collection<?> list) {
            for (Object p : list) {
                if (p == null) {
                    continue;
                }
                String perm = p.toString().trim();
                if (perm.isEmpty()) {
                    continue;
                }
                // AUTHORITY-INJECTION DEFENSE: drop any permissions entry
                // that starts with a reserved prefix — those authorities
                // come only from controlled logic (roles claim ->
                // ROLE_<UPPER>, validated iss -> DOMAIN_<x>, MFA claim ->
                // MFA_SATISFIED). See RESERVED_PREFIXES.
                if (isReserved(perm)) {
                    continue;
                }
                auths.add(new SimpleGrantedAuthority(perm));
            }
        }

        // 4. Legacy isAdmin boolean — adds ROLE_ADMIN when true.
        if (Boolean.TRUE.equals(jwt.getClaim("isAdmin"))) {
            auths.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }

        // 5. MFA_SATISFIED marker (D8 MFA floor, ships dark — default
        // off). Derived ONLY from the BFF-written mfa_satisfied_at claim
        // (checked for freshness). Not a ROLE_ prefix, so it never
        // satisfies a hasRole() check accidentally. The reserved-prefix
        // guard above ensures a forged permissions:["MFA_SATISFIED"] was
        // already dropped before reaching here.
        if (mfa.enabled()
                && Roles.isMfaSatisfied(jwt, now,
                        mfa.freshnessWindowMillis())) {
            auths.add(new SimpleGrantedAuthority(Roles.MFA_SATISFIED));
        }

        // 6. Exactly one DOMAIN_<x> authority derived from the validated
        // issuer. NOT a ROLE_ prefix, so it never satisfies a hasRole()
        // check accidentally. A null registry or null domain (unknown
        // issuer in multi-brand mode) defensively maps to "default"
        // rather than emitting "DOMAIN_null".
        String issuer = jwt.getIssuer() == null
                ? null : jwt.getIssuer().toString();
        String domain = domainRegistry == null
                ? DomainRegistry.DEFAULT_DOMAIN
                : domainRegistry.domainOf(issuer);
        if (domain == null) {
            domain = DomainRegistry.DEFAULT_DOMAIN;
        }
        auths.add(new SimpleGrantedAuthority("DOMAIN_" + domain));

        return auths;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Extracts the role name string from a {@code roles} claim entry,
     * handling both the plain string shape ({@code "admin"}) and the
     * role-object shape ({@code {"name": "admin", ...}}).
     *
     * @param item one element from the JWT {@code roles} claim list; may
     *             be {@code null}
     * @return the trimmed role name string, or {@code ""} for
     *         unrecognised shapes
     */
    private static String roleNameOf(final Object item) {
        if (item instanceof String s) {
            return s;
        }
        if (item instanceof Map<?, ?> m) {
            // Role-object shape: {"name": "admin", "displayName": "..."}
            Object name = m.get("name");
            if (name instanceof String s && !s.isBlank()) {
                return s;
            }
        }
        return "";
    }
}

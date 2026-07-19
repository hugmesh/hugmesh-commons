package systems.hugmesh.commons.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Issuer-URI-to-brand registry — the single source of truth that maps a
 * Casdoor token's cryptographically-validated {@code iss} claim to the
 * brand/domain the principal belongs to.
 *
 * <h2>Responsibility</h2>
 *
 * <p>The platform assigns one Casdoor instance per brand, so the token's
 * {@code iss} claim is the trustworthy tenant discriminator. This registry
 * is the canonical lookup table that {@link CasdoorAuthorities} consults
 * when stamping the {@code DOMAIN_<x>} authority onto the principal's
 * authority set, and that {@link Roles} consults when resolving the domain
 * from a {@link org.springframework.security.oauth2.jwt.Jwt}.
 *
 * <p>Security note: the domain is NEVER derived from a user-settable claim
 * ({@code owner}, {@code org}, {@code aud}) — a user could forge those.
 * The resource server validates {@code iss} cryptographically before any
 * authority is emitted, so an issuer that reaches this registry is already
 * trusted.
 *
 * <p>This is the canonical, shared form. Earlier per-repo copies were
 * logically identical; {@code hugmesh-admin-bff-api} was the richest,
 * adding {@link #knownDomains()} and {@link #isKnownDomain(String)}.
 *
 * <h2>Backward-compatible single-issuer mode</h2>
 *
 * <p>When only
 * {@code spring.security.oauth2.resourceserver.jwt.issuer-uri} is set and
 * {@code app.tenancy.issuers} is empty, the registry seeds exactly one
 * entry mapping that issuer to {@code "default"}, and
 * {@link #domainOf(String)} returns {@code "default"} for every token.
 * Single-issuer clusters emit {@code DOMAIN_default} for every principal
 * and nothing else changes. When no issuer-uri is configured at all, the
 * map stays empty and {@link #domainOf(String)} returns {@code "default"}
 * unconditionally (legacy single-tenant mode).
 *
 * <h2>Multi-brand fail-closed</h2>
 *
 * <p>When {@code app.tenancy.issuers} is populated (format:
 * {@code https://issuer1=brand1,https://issuer2=brand2}), ONLY the listed
 * issuers are trusted. An issuer not in the map returns {@code null} from
 * {@link #domainOf(String)}, and the multi-issuer decoder built from
 * {@link #trustedIssuers()} will have already rejected the token with a
 * {@code 401} before authorities are emitted.
 *
 * <h2>Consumers</h2>
 *
 * <ul>
 *   <li>{@code hugmesh-admin-bff-api} — domain resolution for all
 *       admin operations</li>
 *   <li>{@code hugmesh-federation-api} — manifest domain scoping</li>
 *   <li>{@code hugmesh-user-bff-api} — user-profile / preferences domain
 *       scoping</li>
 *   <li>{@code hugmesh-owncast-bff-api} — streaming metadata domain
 *       scoping</li>
 *   <li>{@code hugmesh-forum-bff-api} — forum domain scoping</li>
 *   <li>{@link TenancyResourceServerConfig} — multi-issuer decoder
 *       allowlist</li>
 *   <li>{@link CasdoorAuthorities} — {@code DOMAIN_<x>} authority
 *       stamping</li>
 * </ul>
 *
 * @see CasdoorAuthorities
 * @see Roles
 * @see PrincipalDomain
 * @see TenancyResourceServerConfig
 * @since hugmesh-commons initial extraction from per-repo copies
 */
@Component
public class DomainRegistry {

    /**
     * The single-tenant / legacy domain that every token maps to when no
     * per-brand registry entry is configured. The converter emits
     * {@code DOMAIN_default} in this case, and per-domain repository
     * queries use {@code WHERE domain = 'default'}.
     */
    public static final String DEFAULT_DOMAIN = "default";

    /**
     * Ordered map of trimmed-issuer-URI to sanitized-brand-name,
     * populated at construction.
     */
    private final Map<String, String> issuerToDomain = new LinkedHashMap<>();

    /**
     * The single configured issuer-uri (back-compat), stored for the
     * {@link #issuerToDomain} seed step.
     */
    private final String singleIssuer;

    /**
     * Constructs the registry from Spring configuration properties.
     *
     * <p>Parsing order:
     * <ol>
     *   <li>If {@code app.tenancy.issuers} is present and non-blank,
     *       parse its comma-separated {@code issuerUri=brand} pairs into
     *       the map. Trailing slashes are stripped from issuer URIs;
     *       brand names are lower-cased and sanitized to
     *       {@code [a-z0-9-]}.</li>
     *   <li>If the multi-issuer map is empty after parsing (no valid
     *       pairs), and the single-issuer property is configured, seed a
     *       single back-compat entry {@code {singleIssuer -> "default"}}
     *       so single-issuer clusters behave identically to before this
     *       registry existed.</li>
     * </ol>
     *
     * @param issuerUri  the back-compat single-issuer URI from
     *                   {@code spring.security.oauth2.resourceserver
     *                   .jwt.issuer-uri} (empty string when not
     *                   configured)
     * @param issuersCsv comma-separated {@code issuerUri=brand} pairs
     *                   from {@code app.tenancy.issuers} (empty string
     *                   when not configured)
     */
    public DomainRegistry(
            @Value("${spring.security.oauth2.resourceserver"
                    + ".jwt.issuer-uri:}") final String issuerUri,
            @Value("${app.tenancy.issuers:}") final String issuersCsv) {
        this.singleIssuer = trimSlash(issuerUri);
        if (issuersCsv != null && !issuersCsv.isBlank()) {
            // Parse "https://casdoor-brand-a=brand-a,..."
            for (String pair : issuersCsv.split(",")) {
                int eq = pair.indexOf('=');
                // skip malformed entries without an '=' separator
                if (eq <= 0) {
                    continue;
                }
                String iss = trimSlash(pair.substring(0, eq).trim());
                String dom = sanitize(pair.substring(eq + 1).trim());
                if (!iss.isEmpty() && !dom.isEmpty()) {
                    issuerToDomain.put(iss, dom);
                }
            }
        }
        // Back-compat: if no multi-issuer pairs were parsed, seed the
        // single known issuer as "default" so a single-issuer cluster
        // stays byte-identical.
        if (issuerToDomain.isEmpty() && !this.singleIssuer.isEmpty()) {
            issuerToDomain.put(this.singleIssuer, DEFAULT_DOMAIN);
        }
    }

    /**
     * Resolves the brand/domain for the given issuer URI.
     *
     * <ul>
     *   <li>When the registry is in single-issuer (or no-config) mode,
     *       returns {@code "default"} unconditionally — the legacy
     *       single-tenant behaviour.</li>
     *   <li>When the registry has a matching entry, returns the
     *       configured brand name (e.g. {@code "acme"},
     *       {@code "globex"}).</li>
     *   <li>When the registry is in multi-brand mode and the issuer is
     *       NOT in the map, returns {@code null} — the caller must treat
     *       this as fail-closed (reject the token / deny the request).
     *       In practice the multi-issuer decoder
     *       ({@link TenancyResourceServerConfig}) will have already
     *       issued a {@code 401} before this is reached.</li>
     * </ul>
     *
     * @param issuer the {@code iss} claim value from the validated JWT
     *               (may be {@code null} — returns {@code "default"} in
     *               no-config mode, or {@code null} in multi-brand mode)
     * @return the resolved brand/domain string, or {@code null} in
     *         multi-brand mode when the issuer is not trusted
     */
    public String domainOf(final String issuer) {
        String iss = trimSlash(issuer);
        // Empty registry means no config at all: single-tenant legacy mode.
        if (issuerToDomain.isEmpty()) {
            return DEFAULT_DOMAIN;
        }
        String d = issuerToDomain.get(iss);
        if (d != null) {
            return d;
        }
        // Multi-brand mode with an unknown issuer: fail closed so callers
        // reject. The decoder built from trustedIssuers() rejects this iss
        // upstream via 401; this null lets any in-process caller also fail
        // closed.
        return null;
    }

    /**
     * Returns {@code true} iff the given issuer is trusted — that is, it
     * resolves to a non-null domain.
     *
     * <p>Used by {@link TenancyResourceServerConfig} to gate whether to
     * build an authentication manager for an issuer.
     *
     * @param issuer the issuer URI to test (trailing slash stripped before
     *               lookup)
     * @return {@code true} iff {@link #domainOf(String)} returns non-null
     *         for this issuer
     */
    public boolean isTrusted(final String issuer) {
        return domainOf(issuer) != null;
    }

    /**
     * Returns the set of all trusted issuer URIs — the allowlist used
     * when building the multi-issuer decoder in
     * {@link TenancyResourceServerConfig}.
     *
     * <p>A token whose {@code iss} is not in this set gets no
     * authentication manager and is rejected with {@code 401} before any
     * authority is emitted.
     *
     * @return an unmodifiable view of the trusted issuer URI strings
     */
    public Set<String> trustedIssuers() {
        return issuerToDomain.keySet();
    }

    /**
     * Returns the set of all known brand/domain names (the values of the
     * issuer-to-domain map).
     *
     * <p>In single-issuer back-compat mode this is exactly
     * {@code {"default"}}. In multi-brand mode it is the set of
     * configured brand names. Used to validate that a DOMAIN-license or
     * service-catalog target refers to a real, reachable brand (a license
     * for an unknown domain would be dead weight).
     *
     * @return a new {@link LinkedHashSet} of the known brand/domain
     *         strings; insertion order matches the configured
     *         {@code app.tenancy.issuers} order
     */
    public Set<String> knownDomains() {
        // Defensive copy: the caller must not be able to mutate the
        // internal map's value collection.
        return new LinkedHashSet<>(issuerToDomain.values());
    }

    /**
     * Returns {@code true} iff {@code domain} is a known, non-default,
     * non-blank brand/domain name.
     *
     * <p>This mirrors the "FIX-NODEFAULT" register guard: a license or
     * service-catalog entry targeting {@code "default"}, a blank string,
     * or an unknown brand is rejected because there is no real per-brand
     * Casdoor instance to back it.
     *
     * @param domain the domain name to validate
     * @return {@code true} iff {@code domain} is present in
     *         {@link #knownDomains()} AND is not {@code "default"} or
     *         blank
     */
    public boolean isKnownDomain(final String domain) {
        if (domain == null || domain.isBlank()) {
            return false;
        }
        // "default" is a back-compat sentinel, not a real per-brand domain.
        if (DEFAULT_DOMAIN.equals(domain)) {
            return false;
        }
        return knownDomains().contains(domain);
    }

    /**
     * Returns {@code true} iff a genuine per-brand multi-issuer registry
     * is configured — specifically, when more than one issuer-to-domain
     * entry exists (i.e. more than just the single back-compat entry).
     *
     * <p>Used by each repo's {@code SecurityConfig} to decide whether to
     * swap in the multi-issuer authentication manager resolver from
     * {@link TenancyResourceServerConfig} or to keep the single-issuer
     * {@code o.jwt(...)} path.
     *
     * @return {@code true} iff {@code app.tenancy.issuers} was parsed
     *         into two or more valid issuer-to-domain pairs
     */
    public boolean isMultiIssuer() {
        return issuerToDomain.size() > 1;
    }

    /**
     * Strips a trailing slash from an issuer URI so
     * {@code "https://casdoor/"} and {@code "https://casdoor"} resolve
     * to the same entry. Returns an empty string for {@code null} or
     * blank input.
     *
     * @param s the issuer URI string to normalise
     * @return the trimmed, slash-stripped string, or {@code ""} for
     *         null/blank input
     */
    private static String trimSlash(final String s) {
        if (s == null) {
            return "";
        }
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }

    /**
     * Sanitizes a brand/domain name to lower-alnum-plus-hyphen so that
     * registry-derived domain strings can be used safely in SQL predicates
     * and authority strings ({@code DOMAIN_<x>}) without
     * special-character injection. Any character outside
     * {@code [a-z0-9-]} is replaced with {@code -}.
     *
     * @param s the raw brand/domain name from configuration
     * @return the sanitized lowercase domain string, or {@code ""} for
     *         null input
     */
    private static String sanitize(final String s) {
        return s == null
                ? ""
                : s.trim().toLowerCase().replaceAll("[^a-z0-9-]", "-");
    }
}

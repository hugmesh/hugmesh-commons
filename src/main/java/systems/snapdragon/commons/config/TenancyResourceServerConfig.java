package systems.snapdragon.commons.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.CasdoorAuthorities;
import systems.snapdragon.commons.security.DomainRegistry;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Config-gated, backward-compatible multi-issuer (per-brand Casdoor)
 * resource-server wiring for reactive Spring Security.
 *
 * <h2>Responsibility</h2>
 *
 * <p>Contributes a per-issuer
 * {@link ReactiveAuthenticationManagerResolver} bean when the deployment
 * is genuinely configured with multiple Casdoor instances
 * ({@code app.tenancy.issuers} carries at least one
 * {@code issuerUri=brand} pair). Each repo's {@code SecurityConfig}
 * additionally swaps onto this resolver only when
 * {@link DomainRegistry#isMultiIssuer()} returns {@code true} (more than
 * the lone back-compat entry), so a single-issuer cluster keeps the
 * existing {@code o.jwt(...)} jwk-set-uri / issuer-uri path completely
 * unchanged.
 *
 * <p>This is the canonical, shared form. Earlier per-repo copies of this
 * configuration were verbatim copies of each other (differing only in
 * package declarations).
 *
 * <h2>Conditional activation guard</h2>
 *
 * <p>The {@code @ConditionalOnExpression} uses a
 * {@code .contains('=')} guard rather than
 * {@code @ConditionalOnProperty(name = "app.tenancy.issuers")}. This is
 * intentional: the property default is the empty string
 * ({@code ${APP_TENANCY_ISSUERS:}}), which
 * {@code @ConditionalOnProperty} would treat as "present and not false"
 * and therefore ALWAYS activate — silently routing single-issuer clusters
 * through the multi-issuer resolver and its OIDC discovery. A valid
 * {@code app.tenancy.issuers} value always contains at least one
 * {@code =} separator, so the guard is reliable.
 *
 * <h2>Fail-closed on unknown issuers</h2>
 *
 * <p>The resolver's allowlist is exactly
 * {@link DomainRegistry#trustedIssuers()}. A token whose {@code iss} is
 * not in that set gets no authentication manager and is rejected with
 * {@code 401} before any authority is emitted. An unknown issuer returns
 * {@code Mono.empty()} from the per-issuer resolver, which
 * {@link JwtIssuerReactiveAuthenticationManagerResolver} translates to
 * {@code 401}.
 *
 * <h2>Byte-identical authority output</h2>
 *
 * <p>The per-issuer {@link JwtReactiveAuthenticationManager} is built
 * here and wired with the SAME {@link CasdoorAuthorities} converter the
 * single-issuer path uses, so the {@code DOMAIN_<x>} authority is emitted
 * in multi-issuer mode too — authority output is byte-identical to the
 * single-issuer path.
 *
 * <h2>D8 MFA floor (ships dark)</h2>
 *
 * <p>The same {@code app.mfa.enabled} (default {@code false}) and
 * {@code app.mfa.freshness-window} (default 10 minutes) that each repo's
 * single-issuer {@code SecurityConfig} reads are threaded into the same
 * {@link CasdoorAuthorities.MfaConfig} here, so the multi-issuer path
 * derives the {@code MFA_SATISFIED} marker byte-identically to the
 * single-issuer path.
 *
 * <h2>Consumers</h2>
 *
 * <ul>
 *   <li>{@code snapdragon-admin-bff-api} — multi-issuer swap-in</li>
 *   <li>{@code snapdragon-federation-api} — multi-issuer swap-in</li>
 *   <li>{@code snapdragon-user-bff} — multi-issuer swap-in</li>
 *   <li>{@code snapdragon-owncast-bff} — multi-issuer swap-in</li>
 *   <li>{@code snapdragon-forum-bff} — multi-issuer swap-in</li>
 * </ul>
 *
 * @see DomainRegistry
 * @see CasdoorAuthorities
 * @since snapdragon-commons initial extraction from per-repo copies
 */
@Configuration
// Fire ONLY when app.tenancy.issuers genuinely carries issuer=domain
// pairs. The '=' guard makes the empty ${APP_TENANCY_ISSUERS:} default
// a no-op: an empty string is "present and not false" to
// @ConditionalOnProperty, which would have activated this bean (and
// silently routed single-issuer clusters through the resolver / OIDC
// discovery). A valid CSV always contains at least one '='.
@ConditionalOnExpression("'${app.tenancy.issuers:}'.contains('=')")
public class TenancyResourceServerConfig {

    /** Registry used to resolve issuer URIs to brand/domain names. */
    private final DomainRegistry domainRegistry;

    /**
     * Explicit issuer-URI of the lone back-compat issuer (the
     * single-issuer
     * {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}).
     * Paired with {@link #backCompatJwkSetUri} to build a
     * discovery-free decoder for the back-compat issuer when a
     * jwk-set-uri is also configured, avoiding an OIDC discovery
     * round-trip on first request for an already-known issuer.
     */
    private final String backCompatIssuer;

    /**
     * Explicit jwk-set-uri of the lone back-compat issuer — used to
     * build the per-issuer decoder WITHOUT triggering OIDC discovery.
     * Empty on pure multi-brand configs where each per-brand issuer
     * discovers its JWKS from its own {@code iss}.
     */
    private final String backCompatJwkSetUri;

    /**
     * D8 MFA floor toggle — ships DARK. The same
     * {@code app.mfa.enabled} property (default {@code false}) the
     * single-issuer {@code SecurityConfig} reads, so the
     * {@code MFA_SATISFIED} marker derivation is identical on both
     * paths.
     */
    private final boolean mfaEnabled;

    /**
     * D8 MFA freshness window in milliseconds. The same
     * {@code app.mfa.freshness-window} (default 10 minutes /
     * {@code 600000} ms) the single-issuer {@code SecurityConfig}
     * reads, threaded into {@link CasdoorAuthorities.MfaConfig} to
     * keep both paths byte-identical.
     */
    private final long mfaFreshnessWindow;

    /**
     * Constructs the multi-issuer resource-server configuration from
     * Spring properties.
     *
     * @param registry        the issuer-to-domain registry that supplies
     *                        the trusted issuer allowlist and domain
     *                        lookups
     * @param issuerUri       the existing single-issuer URI from
     *                        {@code spring.security.oauth2.resourceserver
     *                        .jwt.issuer-uri}; empty when not configured
     * @param jwkSetUri       the existing single-issuer JWKS URI from
     *                        {@code spring.security.oauth2.resourceserver
     *                        .jwt.jwk-set-uri}; empty when not configured
     * @param mfaEnabledParam whether the D8 MFA floor is active
     *                        ({@code app.mfa.enabled}; default
     *                        {@code false})
     * @param freshnessWindow MFA stamp freshness window in milliseconds
     *                        ({@code app.mfa.freshness-window}; default
     *                        {@code 600000} = 10 minutes)
     */
    public TenancyResourceServerConfig(
            final DomainRegistry registry,
            @Value("${spring.security.oauth2.resourceserver"
                    + ".jwt.issuer-uri:}") final String issuerUri,
            @Value("${spring.security.oauth2.resourceserver"
                    + ".jwt.jwk-set-uri:}") final String jwkSetUri,
            @Value("${app.mfa.enabled:false}") final boolean mfaEnabledParam,
            @Value("${app.mfa.freshness-window:600000}")
            final long freshnessWindow) {
        this.domainRegistry = registry;
        this.backCompatIssuer = trimSlash(issuerUri);
        this.backCompatJwkSetUri =
                jwkSetUri == null ? "" : jwkSetUri.trim();
        this.mfaEnabled = mfaEnabledParam;
        this.mfaFreshnessWindow = freshnessWindow;
    }

    // -----------------------------------------------------------------------
    // Bean
    // -----------------------------------------------------------------------

    /**
     * Produces the per-issuer
     * {@link ReactiveAuthenticationManagerResolver} that routes each
     * inbound JWT to the authentication manager for its {@code iss}.
     *
     * <p>The resolver lazily builds one
     * {@link JwtReactiveAuthenticationManager} per trusted issuer on
     * first encounter (decoding involves synchronous OIDC discovery —
     * see below) and caches it in a {@link ConcurrentHashMap} so
     * subsequent requests hit the warm entry without reconstruction.
     *
     * <p>Only the trusted issuers from
     * {@link DomainRegistry#trustedIssuers()} get a manager; an unknown
     * {@code iss} yields {@code Mono.empty()}, which the delegating
     * resolver translates to a {@code 401} before any authority is
     * emitted (fail-closed).
     *
     * <p>Optionally warms the issuer cache on a daemon thread at startup
     * — see {@link #warmIssuersIfEnabled(Map)} for the trade-off.
     *
     * @return a resolver that maps each request's JWT issuer to the
     *         correct {@link ReactiveAuthenticationManager}; never
     *         {@code null}
     */
    @Bean
    ReactiveAuthenticationManagerResolver<ServerWebExchange>
            tenantAuthManagerResolver() {
        // Cache one manager per trusted issuer. Decoder construction does
        // network discovery — build lazily on first encounter, never
        // rebuild per request.
        var byIssuer =
                new ConcurrentHashMap<String, ReactiveAuthenticationManager>();

        // Per-issuer resolver: ONLY trusted issuers (registry keys) get
        // a manager. An unknown iss yields Mono.empty() -> 401
        // (fail-closed).
        ReactiveAuthenticationManagerResolver<String> byIssuerResolver =
                issuer -> {
                    if (issuer == null
                            || !domainRegistry.isTrusted(issuer)) {
                        return Mono.empty();
                    }
                    return Mono.just(
                            byIssuer.computeIfAbsent(
                                    issuer, this::managerForIssuer));
                };

        var delegate =
                new JwtIssuerReactiveAuthenticationManagerResolver(
                        byIssuerResolver);

        // Opt-in, off-request-path decoder warmup — ships DARK (default
        // off). See warmIssuersIfEnabled for trade-off details.
        warmIssuersIfEnabled(byIssuer);

        return delegate::resolve;
    }

    // -----------------------------------------------------------------------
    // Warmup
    // -----------------------------------------------------------------------

    /**
     * Best-effort, opt-in pre-build of every trusted issuer's
     * authentication manager on a daemon thread, avoiding a cold-start
     * latency spike on the first request to each issuer.
     *
     * <h3>The cold-start problem</h3>
     *
     * <p>{@link #managerForIssuer(String)} calls
     * {@link #decoderForIssuer(String)}, which may call
     * {@link ReactiveJwtDecoders#fromIssuerLocation(String)} — a
     * SYNCHRONOUS OIDC discovery round-trip (blocking HTTP) at
     * decoder-construction time. On the lazy path, this cost is paid
     * inside {@code computeIfAbsent} on the first request that touches a
     * given issuer, causing that request to experience a cold-start
     * latency spike.
     *
     * <h3>The warmup trade-off</h3>
     *
     * <p>When enabled, this method starts a single daemon thread that
     * iterates every trusted issuer and pre-builds its manager before any
     * request arrives. Cold-start latency disappears for all subsequent
     * requests. The thread is daemonic so it never blocks JVM shutdown.
     *
     * <p>This is SAFE and INERT BY DEFAULT: gated on the
     * {@code app.tenancy.warmup-issuers} system property or
     * {@code APP_TENANCY_WARMUP_ISSUERS} environment variable (default:
     * off). Failures during warmup are swallowed — a transient Casdoor
     * outage at boot can never crash startup or fail-open; the lazy path
     * still rebuilds on the first affected request.
     *
     * @param byIssuer the shared issuer-to-manager cache to pre-populate
     */
    private void warmIssuersIfEnabled(
            final Map<String, ReactiveAuthenticationManager> byIssuer) {
        if (!warmupEnabled()) {
            return; // DARK default — no change to the existing lazy path.
        }
        Set<String> issuers = domainRegistry.trustedIssuers();
        if (issuers.isEmpty()) {
            return;
        }
        // Delegate warmup body to a named helper to satisfy lambda-length limits.
        Thread warmer = new Thread(
                () -> warmAllIssuers(issuers, byIssuer),
                "tenancy-issuer-warmup");
        // Daemon so this thread never prevents JVM shutdown.
        warmer.setDaemon(true);
        warmer.start();
    }

    /**
     * Pre-builds every trusted issuer's authentication manager so the
     * first real request to each issuer hits a warm cache rather than
     * paying the synchronous OIDC discovery cost on the request thread.
     *
     * <p>Failures are swallowed: a transient Casdoor outage at boot must
     * never crash startup or fail-open; the lazy path rebuilds absent
     * entries on the first affected request.
     *
     * @param issuers  the set of trusted issuer URIs to warm
     * @param byIssuer the shared issuer-to-manager cache to pre-populate
     */
    private void warmAllIssuers(
            final Set<String> issuers,
            final Map<String, ReactiveAuthenticationManager> byIssuer) {
        for (String iss : issuers) {
            try {
                // computeIfAbsent is thread-safe; if the lazy path already
                // built the manager for this issuer this is a harmless no-op.
                byIssuer.computeIfAbsent(iss, this::managerForIssuer);
            } catch (RuntimeException ignored) {
                // Discovery unreachable at boot (Casdoor not yet ready).
                // Leave the entry absent; the lazy path rebuilds on first
                // request.
            }
        }
    }

    /**
     * Returns {@code true} iff the opt-in issuer warmup is enabled via
     * the system property {@code app.tenancy.warmup-issuers} or the
     * environment variable {@code APP_TENANCY_WARMUP_ISSUERS}.
     *
     * <p>Accepts {@code "true"} or {@code "1"} (case-insensitive,
     * whitespace-trimmed). Defaults to {@code false} so the existing
     * lazy path is preserved unless an operator explicitly opts in.
     *
     * @return {@code true} iff warmup is explicitly enabled;
     *         {@code false} by default
     */
    private static boolean warmupEnabled() {
        // System property takes precedence; fall back to env variable.
        String v = System.getProperty("app.tenancy.warmup-issuers");
        if (v == null || v.isBlank()) {
            v = System.getenv("APP_TENANCY_WARMUP_ISSUERS");
        }
        return v != null
                && ("true".equalsIgnoreCase(v.trim())
                        || "1".equals(v.trim()));
    }

    // -----------------------------------------------------------------------
    // Per-issuer manager and decoder construction
    // -----------------------------------------------------------------------

    /**
     * Builds the {@link JwtReactiveAuthenticationManager} for a single
     * trusted issuer, wired with the same {@link CasdoorAuthorities}
     * converter the single-issuer path uses. This ensures the
     * {@code DOMAIN_<x>} authority and the {@code MFA_SATISFIED} marker
     * are emitted identically in both paths.
     *
     * <p>Called at most once per issuer (via {@code computeIfAbsent}) —
     * the result is cached in the shared map for the lifetime of the bean.
     *
     * @param issuer the trusted issuer URI to build a manager for
     * @return the configured {@link ReactiveAuthenticationManager} for
     *         that issuer
     */
    private ReactiveAuthenticationManager managerForIssuer(
            final String issuer) {
        var mgr =
                new JwtReactiveAuthenticationManager(
                        decoderForIssuer(issuer));
        var converter = new ReactiveJwtAuthenticationConverter();
        // Wire the same Casdoor authorities converter as the single-issuer
        // path — both paths emit byte-identical authority sets.
        converter.setJwtGrantedAuthoritiesConverter(
                authoritiesConverter());
        mgr.setJwtAuthenticationConverter(converter);
        return mgr;
    }

    /**
     * Builds the {@link ReactiveJwtDecoder} for a single trusted issuer.
     *
     * <p>Two cases:
     * <ul>
     *   <li>The lone back-compat issuer that also has a configured
     *       {@code jwk-set-uri}: builds a
     *       {@link NimbusReactiveJwtDecoder} directly from the JWKS URI
     *       (no OIDC discovery round-trip) and sets the standard
     *       {@code exp}/{@code nbf} plus issuer-binding validators.</li>
     *   <li>Any other per-brand issuer: uses
     *       {@link ReactiveJwtDecoders#fromIssuerLocation(String)} OIDC
     *       discovery — the correct behavior for a genuinely multi-brand
     *       deployment where each per-brand Casdoor exposes its own
     *       {@code /.well-known/openid-configuration}.</li>
     * </ul>
     *
     * @param issuer the trusted issuer URI to build a decoder for
     * @return the configured {@link ReactiveJwtDecoder} for that issuer
     */
    private ReactiveJwtDecoder decoderForIssuer(final String issuer) {
        String iss = trimSlash(issuer);
        // Use the discovery-free path when this IS the lone configured
        // back-compat issuer AND a jwk-set-uri is also configured. Both
        // conditions required: we need the JWKS URI to skip discovery, and
        // we need to confirm the issuer matches so we don't route a genuine
        // per-brand issuer through a stale JWKS.
        if (!backCompatJwkSetUri.isEmpty()
                && !backCompatIssuer.isEmpty()
                && backCompatIssuer.equals(iss)) {
            NimbusReactiveJwtDecoder decoder =
                    NimbusReactiveJwtDecoder
                            .withJwkSetUri(backCompatJwkSetUri).build();
            // Add the standard exp/nbf validators PLUS an issuer-binding
            // validator so a token from a different issuer can't be
            // accepted by the wrong decoder.
            OAuth2TokenValidator<Jwt> withIssuer =
                    JwtValidators.createDefaultWithIssuer(iss);
            decoder.setJwtValidator(withIssuer);
            return decoder;
        }
        // Per-brand issuer: perform OIDC discovery from the issuer
        // location to obtain its JWKS URI automatically.
        return ReactiveJwtDecoders.fromIssuerLocation(iss);
    }

    /**
     * Builds the {@link CasdoorAuthorities} JWT-to-
     * {@link GrantedAuthority} converter wired to the shared
     * {@link DomainRegistry} and the current
     * {@link CasdoorAuthorities.MfaConfig}.
     *
     * <p>This is the identical converter shape used by each repo's
     * single-issuer {@code SecurityConfig}, kept in sync via the shared
     * {@link CasdoorAuthorities} factory method.
     *
     * @return a converter emitting the Snapdragon authority set as a
     *         reactive {@link Flux}
     */
    private Converter<Jwt, Flux<GrantedAuthority>> authoritiesConverter() {
        return CasdoorAuthorities.converter(
                domainRegistry,
                new CasdoorAuthorities.MfaConfig(
                        mfaEnabled, mfaFreshnessWindow));
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Strips a trailing slash from an issuer URI so
     * {@code "https://casdoor/"} and {@code "https://casdoor"} resolve
     * to the same registry entry. Returns an empty string for {@code null}
     * or blank input.
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
}

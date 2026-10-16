package net.hugmesh.commons.config;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Date;
import net.hugmesh.commons.security.DomainRegistry;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit test for {@link TenancyResourceServerConfig}'s per-issuer allowlist gate.
 *
 * <p>These tests never touch the network. The DENY paths return before any
 * decoder is constructed, and the single ALLOW path is routed through the
 * back-compat {@code jwk-set-uri} branch of {@code decoderForIssuer}, which
 * builds a {@code NimbusReactiveJwtDecoder} without an OIDC discovery
 * round-trip. No {@code ReactiveJwtDecoders.fromIssuerLocation} call is ever
 * made, so no testcontainer or outbound HTTP is required.
 */
class TenancyResourceServerConfigTest {

    private static final String BRAND_A = "https://idp.brandx.example";
    private static final String BRAND_B = "https://idp.brandy.example";
    private static final String EVIL = "https://evil.attacker.tld";

    /** Builds the config under test with no back-compat issuer/jwks wiring. */
    private static TenancyResourceServerConfig config(final DomainRegistry r) {
        return new TenancyResourceServerConfig(r, "", "", false, 600000L);
    }

    /** Drives the package-private per-issuer resolver directly. */
    private static ReactiveAuthenticationManagerResolver<String> resolverFor(
            final TenancyResourceServerConfig cfg,
            final Map<String, ReactiveAuthenticationManager> cache) {
        return cfg.byIssuerResolver(cache);
    }

    @Nested
    class GuardPremise {

        /**
         * PREMISE GUARD — NOT an endorsement of this behaviour.
         *
         * <p>{@link DomainRegistry#isTrusted(String)} FAILS OPEN on an empty
         * registry: it delegates to {@code domainOf}, which short-circuits to
         * the legacy single-tenant {@code "default"} without inspecting its
         * argument. {@link TenancyResourceServerConfig} therefore must NOT gate
         * on {@code isTrusted}, and deliberately does not.
         *
         * <p>If you are here because you "fixed" {@code domainOf} to stop
         * returning {@code "default"} on an empty registry: legacy single-tenant
         * clusters silently depend on that default and changing it is a
         * live-boot behaviour change across every consumer. Do not change it to
         * make this test pass. This assertion exists so that the dependency is
         * explicit rather than accidental — the resolver's own fail-closed
         * tests below must keep passing either way.
         */
        @Test
        void isTrusted_failsOpen_onEmptyRegistry_soTheResolverMustNotUseIt() {
            // "=brand" contains '=' (so the @ConditionalOnExpression guard fires
            // and the bean is ACTIVE) but parses to ZERO valid pairs, and with
            // no issuer-uri there is no back-compat seed => EMPTY registry.
            DomainRegistry empty = new DomainRegistry("", "=brand");

            assertThat(empty.trustedIssuers()).isEmpty();
            assertThat(empty.isMultiIssuer()).isFalse();

            // The fail-open, pinned:
            assertThat(empty.isTrusted(EVIL)).isTrue();
            assertThat(empty.domainOf(EVIL))
                    .isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        }
    }

    @Nested
    class EmptyAllowlistDeniesEveryIssuer {

        /**
         * THE FIX. The bean is active (the CSV contains '=') yet the registry
         * parsed to zero pairs. An attacker-chosen iss must NOT resolve to a
         * manager — reaching {@code decoderForIssuer} here would mean OIDC
         * discovery against an attacker-controlled URL.
         */
        @Test
        void activeBeanWithUnparsableCsv_deniesAttackerIssuer() {
            DomainRegistry empty = new DomainRegistry("", "=brand");
            var cache = new ConcurrentHashMap<String,
                    ReactiveAuthenticationManager>();

            var mgr = resolverFor(config(empty), cache).resolve(EVIL).block();

            assertThat(mgr).isNull();
            // Nothing was constructed => no discovery was attempted.
            assertThat(cache).isEmpty();
        }

        /** The blank-domain variant of the same unparsable-CSV state. */
        @Test
        void activeBeanWithBlankDomainCsv_deniesAttackerIssuer() {
            DomainRegistry empty = new DomainRegistry("", "https://iss=");
            assertThat(empty.trustedIssuers()).isEmpty();

            var cache = new ConcurrentHashMap<String,
                    ReactiveAuthenticationManager>();
            var mgr = resolverFor(config(empty), cache).resolve(EVIL).block();

            assertThat(mgr).isNull();
            assertThat(cache).isEmpty();
        }

        /** An empty allowlist denies even a plausible-looking real issuer. */
        @Test
        void emptyAllowlist_deniesEvenAWellFormedIssuer() {
            DomainRegistry empty = new DomainRegistry("", "=brand");
            var cache = new ConcurrentHashMap<String,
                    ReactiveAuthenticationManager>();

            assertThat(resolverFor(config(empty), cache).resolve(BRAND_A)
                    .block()).isNull();
            assertThat(cache).isEmpty();
        }

        @Test
        void nullAndBlankIssuers_areDenied() {
            DomainRegistry empty = new DomainRegistry("", "=brand");
            var cache = new ConcurrentHashMap<String,
                    ReactiveAuthenticationManager>();
            var resolver = resolverFor(config(empty), cache);

            assertThat(resolver.resolve(null).block()).isNull();
            assertThat(resolver.resolve("").block()).isNull();
            assertThat(resolver.resolve("   ").block()).isNull();
        }
    }

    @Nested
    class PopulatedAllowlistStillFailsClosedForUnknownIssuers {

        private final DomainRegistry multi = new DomainRegistry(
                "", BRAND_A + "=brandx," + BRAND_B + "=brandy");

        @Test
        void unknownIssuer_isDenied() {
            var cache = new ConcurrentHashMap<String,
                    ReactiveAuthenticationManager>();

            assertThat(resolverFor(config(multi), cache).resolve(EVIL).block())
                    .isNull();
            assertThat(cache).isEmpty();
        }

        /**
         * A trusted-issuer PREFIX must not smuggle an attacker host through:
         * strict equality, never startsWith/contains.
         */
        @Test
        void issuerPrefixOfATrustedIssuer_isDenied() {
            var cache = new ConcurrentHashMap<String,
                    ReactiveAuthenticationManager>();
            var resolver = resolverFor(config(multi), cache);

            assertThat(resolver.resolve(BRAND_A + ".evil.tld").block()).isNull();
            assertThat(resolver.resolve(BRAND_A + "@evil.tld").block()).isNull();
            assertThat(cache).isEmpty();
        }
    }

    @Nested
    class TrustedIssuerResolvesAndCachesCanonically {

        // The lone back-compat issuer WITH a jwk-set-uri: decoderForIssuer
        // takes the discovery-free NimbusReactiveJwtDecoder branch, so this
        // allow-path test makes no network call.
        private TenancyResourceServerConfig backCompatConfig(
                final DomainRegistry r) {
            return new TenancyResourceServerConfig(
                    r, BRAND_A, BRAND_A + "/jwks", false, 600000L);
        }

        @Test
        void trustedIssuer_resolvesToAManager() {
            DomainRegistry multi = new DomainRegistry(
                    "", BRAND_A + "=brandx," + BRAND_B + "=brandy");
            var cache = new ConcurrentHashMap<String,
                    ReactiveAuthenticationManager>();

            var mgr = resolverFor(backCompatConfig(multi), cache)
                    .resolve(BRAND_A).block();

            assertThat(mgr).isNotNull();
            assertThat(cache).containsOnlyKeys(BRAND_A);
        }

        /**
         * Cache-key canonicalisation (waste, not vulnerability): the allowlist
         * lookup returns the SET's element, so "https://x" and "https://x/"
         * share ONE manager instead of building a duplicate per slash variant.
         */
        @Test
        void slashVariantsShareOneCachedManager() {
            DomainRegistry multi = new DomainRegistry(
                    "", BRAND_A + "=brandx," + BRAND_B + "=brandy");
            var cache = new ConcurrentHashMap<String,
                    ReactiveAuthenticationManager>();
            var resolver = resolverFor(backCompatConfig(multi), cache);

            var bare = resolver.resolve(BRAND_A).block();
            var slashed = resolver.resolve(BRAND_A + "/").block();

            assertThat(bare).isNotNull();
            assertThat(slashed).isNotNull();
            // Same instance, one cache entry keyed by the canonical form.
            assertThat(slashed).isSameAs(bare);
            assertThat(cache).containsOnlyKeys(BRAND_A);
        }
    }
    /**
     * Issue #9: the back-compat decoder is discovery-free, so a
     * {@code jwk-set-uri} that does not belong to the back-compat issuer (or
     * is simply unreachable) makes the key fetch fail. That failure is not a
     * bad token, but nothing is granted either way, so it must surface as a
     * {@code 401} (invalid bearer token), not as the authentication-service
     * error that becomes a {@code 500}.
     */
    @Nested
    class BackCompatKeyFetchFailureIsUnauthorized {

        /** Port 1 refuses the connection at once, so no real host is hit. */
        private static final String DEAD_JWKS = "http://127.0.0.1:1/jwks";

        private String signedToken(final String issuer)
                throws JOSEException {
            RSAKey key = new RSAKeyGenerator(2048).generate();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject("someone")
                    .expirationTime(new Date(
                            System.currentTimeMillis() + 600_000L))
                    .build();
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.RS256), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        }

        @Test
        void unreachableJwkSetUri_isInvalidBearerToken_notAServiceError()
                throws Exception {
            DomainRegistry multi = new DomainRegistry(
                    "", BRAND_A + "=brandx," + BRAND_B + "=brandy");
            var cfg = new TenancyResourceServerConfig(
                    multi, BRAND_A, DEAD_JWKS, false, 600000L);
            var cache = new ConcurrentHashMap<String,
                    ReactiveAuthenticationManager>();
            var mgr = resolverFor(cfg, cache).resolve(BRAND_A).block();
            assertThat(mgr).isNotNull();

            var token = new BearerTokenAuthenticationToken(
                    signedToken(BRAND_A));

            assertThatThrownBy(() -> mgr.authenticate(token).block())
                    .isInstanceOf(InvalidBearerTokenException.class);
        }
    }
}

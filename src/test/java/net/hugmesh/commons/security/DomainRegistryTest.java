package net.hugmesh.commons.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for the canonical {@link DomainRegistry}: single-issuer back-compat
 * (everything is {@code "default"}), multi-brand fail-closed (unknown issuer -&gt;
 * {@code null}), trailing-slash normalisation, and the admin-derived
 * {@code knownDomains}/{@code isKnownDomain} validation helpers.
 */
class DomainRegistryTest {

    @Nested
    class SingleIssuerBackCompat {

        @Test
        void noConfig_everyIssuerIsDefault() {
            DomainRegistry r = new DomainRegistry("", "");
            assertThat(r.domainOf("https://anything")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(r.domainOf(null)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(r.isMultiIssuer()).isFalse();
        }

        @Test
        void loneIssuerUri_mapsToDefault() {
            DomainRegistry r = new DomainRegistry("https://casdoor:8000", "");
            assertThat(r.domainOf("https://casdoor:8000")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(r.domainOf("https://casdoor:8000/")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(r.isMultiIssuer()).isFalse();
        }
    }

    @Nested
    class MultiBrandFailClosed {

        private final DomainRegistry r = new DomainRegistry(
                "", "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

        @Test
        void trustedIssuers_resolveTheirBrand() {
            assertThat(r.domainOf("https://idp.brandx.example")).isEqualTo("brandx");
            assertThat(r.domainOf("https://idp.brandy.example")).isEqualTo("brandy");
            assertThat(r.isMultiIssuer()).isTrue();
        }

        @Test
        void unknownIssuer_failsClosedNull() {
            assertThat(r.domainOf("https://evil.attacker.example")).isNull();
            assertThat(r.isTrusted("https://evil.attacker.example")).isFalse();
            assertThat(r.domainOf(null)).isNull();
        }

        @Test
        void trustedIssuerSet_isTheAllowlist() {
            assertThat(r.trustedIssuers())
                    .containsExactlyInAnyOrder("https://idp.brandx.example", "https://idp.brandy.example");
        }
    }

    /**
     * The malformed-{@code app.tenancy.issuers} parse branches — the
     * {@code eq <= 0} skip, the blank-issuer/blank-domain skip, and the
     * separator-less value. Current production behaviour silently depends on
     * these: a value that CONTAINS {@code '='} but parses to ZERO valid pairs still
     * activates {@link net.hugmesh.commons.config.TenancyResourceServerConfig}'s
     * {@code @ConditionalOnExpression}({@code .contains('=')}) while leaving
     * this registry EMPTY.
     */
    @Nested
    class MalformedIssuersCsv {

        @Test
        void leadingSeparator_isSkipped_leavingRegistryEmpty() {
            // eq == 0 -> the `eq <= 0` skip fires. The TenancyResourceServerConfig
            // bean is active (the value contains '=') while the map stays empty.
            DomainRegistry r = new DomainRegistry("", "=brand");
            assertThat(r.trustedIssuers()).isEmpty();
            assertThat(r.knownDomains()).isEmpty();
            assertThat(r.isMultiIssuer()).isFalse();
        }

        @Test
        void blankDomain_isSkipped_leavingRegistryEmpty() {
            // sanitize("") -> "" -> the !dom.isEmpty() guard skips the pair.
            DomainRegistry r = new DomainRegistry("", "https://iss=");
            assertThat(r.trustedIssuers()).isEmpty();
            assertThat(r.isMultiIssuer()).isFalse();
        }

        @Test
        void noSeparatorAtAll_isSkipped_leavingRegistryEmpty() {
            // eq == -1 -> skipped. Unlike the other cases here, this value ALSO
            // leaves the TenancyResourceServerConfig bean inactive: no '=' to match.
            DomainRegistry r = new DomainRegistry("", "https://iss-without-eq");
            assertThat(r.trustedIssuers()).isEmpty();
            assertThat(r.isMultiIssuer()).isFalse();
        }

        @Test
        void malformedCsv_stillSeedsTheBackCompatIssuerWhenOneIsConfigured() {
            // Zero valid pairs must still fall through to the single-issuer seed:
            // this is the back-compat contract.
            DomainRegistry r = new DomainRegistry("https://casdoor:8000", "=brand");
            assertThat(r.trustedIssuers()).containsExactly("https://casdoor:8000");
            assertThat(r.domainOf("https://casdoor:8000"))
                    .isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(r.isMultiIssuer()).isFalse();
        }

        @Test
        void mixedCsv_keepsOnlyTheValidPairs() {
            DomainRegistry r = new DomainRegistry(
                    "", "=skipped,https://good.example=good,https://blank=,bare");
            assertThat(r.trustedIssuers()).containsExactly("https://good.example");
            assertThat(r.domainOf("https://good.example")).isEqualTo("good");
            assertThat(r.isMultiIssuer()).isFalse();
        }

        @Test
        void emptyRegistry_failsOpenToDefault_legacySingleTenantContract() {
            // PINNED LEGACY BEHAVIOUR, not an endorsement: this test asserts a
            // known fail-open so a change to it is caught. domainOf short-circuits
            // to "default" on an empty registry WITHOUT inspecting its argument, so
            // isTrusted answers true for ANY issuer. Legacy single-tenant clusters
            // silently depend on that default, which is why
            // TenancyResourceServerConfig does NOT use isTrusted() and gates on
            // strict trustedIssuers() containment instead.
            DomainRegistry r = new DomainRegistry("", "=brand");
            assertThat(r.domainOf("https://evil.attacker.tld"))
                    .isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(r.isTrusted("https://evil.attacker.tld")).isTrue();
        }
    }

    @Nested
    class KnownDomainValidation {

        private final DomainRegistry r = new DomainRegistry(
                "", "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

        @Test
        void knownDomains_areTheBrandValues() {
            assertThat(r.knownDomains()).containsExactlyInAnyOrder("brandx", "brandy");
        }

        @Test
        void isKnownDomain_rejectsDefaultBlankUnknown() {
            assertThat(r.isKnownDomain("brandx")).isTrue();
            assertThat(r.isKnownDomain("default")).isFalse();
            assertThat(r.isKnownDomain("")).isFalse();
            assertThat(r.isKnownDomain(null)).isFalse();
            assertThat(r.isKnownDomain("nonexistent")).isFalse();
        }
    }
}

package systems.snapdragon.commons.security;

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

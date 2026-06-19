package systems.snapdragon.commons.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for the canonical {@link Roles}: the roles-claim is read for the Jwt
 * predicates ({@code isSuperadmin}/{@code isImageBuilder}); {@code domainOf(Jwt)} is
 * issuer-keyed; both authority-collection overloads FAIL CLOSED on zero or &gt;1
 * {@code DOMAIN_}; the MFA stamp is freshness-windowed and fail-closed.
 */
class RolesTest {

    private static Jwt.Builder base() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u");
    }

    @Nested
    class RolesClaimMapping {

        @Test
        void fromJwt_handlesStringAndObjectShapes_upperCased() {
            assertThat(Roles.fromJwt(base().claim("roles", List.of("admin", "player")).build()))
                    .containsExactly("ADMIN", "PLAYER");
            assertThat(Roles.fromJwt(base()
                    .claim("roles", List.of(java.util.Map.of("name", "admin"), java.util.Map.of("name", "user")))
                    .build()))
                    .containsExactly("ADMIN", "USER");
        }

        @Test
        void fromJwt_skipsBlankEntries_andNullJwt() {
            assertThat(Roles.fromJwt(base().claim("roles", List.of("", "  ")).build())).isEmpty();
            assertThat(Roles.fromJwt(null)).isEmpty();
        }

        @Test
        void has_isCaseInsensitive() {
            Jwt jwt = base().claim("roles", List.of("Admin")).build();
            assertThat(Roles.has(jwt, "admin")).isTrue();
            assertThat(Roles.has(jwt, "ADMIN")).isTrue();
            assertThat(Roles.has(jwt, "mod")).isFalse();
        }

        @Test
        void isAdmin_fromRolesClaimOrLegacyBoolean() {
            assertThat(Roles.isAdmin(base().claim("roles", List.of("admin")).build())).isTrue();
            assertThat(Roles.isAdmin(base().claim("isAdmin", true).build())).isTrue();
            assertThat(Roles.isAdmin(base().claim("roles", List.of("user")).build())).isFalse();
        }
    }

    @Nested
    class UserSituational {

        @Test
        void isSuperadmin_readsRolesClaimOnly_bothSpellings() {
            assertThat(Roles.isSuperadmin(base().claim("roles", List.of("superadmin")).build())).isTrue();
            assertThat(Roles.isSuperadmin(base().claim("roles", List.of("super-admin")).build())).isTrue();
            assertThat(Roles.isSuperadmin(base().claim("roles", List.of("super_admin")).build())).isTrue();
            assertThat(Roles.isSuperadmin(base().claim("roles", List.of("admin")).build())).isFalse();
        }

        @Test
        void isImageBuilder_readsRolesClaimOnly() {
            assertThat(Roles.isImageBuilder(base().claim("roles", List.of("image-builder")).build())).isTrue();
            assertThat(Roles.isImageBuilder(base().claim("roles", List.of("image_builder")).build())).isTrue();
            assertThat(Roles.isImageBuilder(base().claim("roles", List.of("user")).build())).isFalse();
        }

        @Test
        void domainOfJwt_isIssuerKeyed() {
            DomainRegistry r = new DomainRegistry("", "https://idp.brandx.example=brandx");
            Jwt jwt = base().issuer("https://idp.brandx.example").build();
            assertThat(Roles.domainOf(jwt, r)).isEqualTo("brandx");
        }

        @Test
        void casdoorIdOf_prefersSubjectThenIdClaim() {
            assertThat(Roles.casdoorIdOf(base().subject("sub-1").build())).isEqualTo("sub-1");
            // No subject -> falls back to the id claim.
            Jwt noSub = Jwt.withTokenValue("t").header("alg", "none")
                    .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                    .claim("id", "id-7").build();
            assertThat(Roles.casdoorIdOf(noSub)).isEqualTo("id-7");
        }
    }

    @Nested
    class CrossUserFailClosed {

        @Test
        void superadmin_cannotBeForgedByPermissionAuthority() {
            // isSuperadmin reads the roles CLAIM, not the authority list — a forged
            // permission can never make it true (and the converter strips it anyway).
            assertThat(Roles.isSuperadmin(base().claim("permissions", List.of("ROLE_SUPERADMIN")).build()))
                    .isFalse();
        }

        @Test
        void isSuperadmin_authorityForms_bothSpellings() {
            assertThat(Roles.isSuperadmin(List.of(new SimpleGrantedAuthority("ROLE_SUPERADMIN")))).isTrue();
            assertThat(Roles.isSuperadmin(List.of(new SimpleGrantedAuthority("ROLE_SUPER-ADMIN")))).isTrue();
            assertThat(Roles.isSuperadmin(List.of(new SimpleGrantedAuthority("ROLE_ADMIN")))).isFalse();
            assertThat(Roles.isSuperadminNames(Set.of("ROLE_SUPERADMIN"))).isTrue();
            assertThat(Roles.isSuperadminNames(Set.of("ROLE_ADMIN"))).isFalse();
            assertThat(Roles.isSuperadminNames(null)).isFalse();
        }

        @Test
        void domainOfAuthorities_failsClosedOnZeroOrMany() {
            assertThat(Roles.domainOf(List.of())).isNull();                               // zero
            assertThat(Roles.domainOf(List.of(new SimpleGrantedAuthority("DOMAIN_brandx"))))
                    .isEqualTo("brandx");                                                 // exactly one
            assertThat(Roles.domainOf(List.of(
                    new SimpleGrantedAuthority("DOMAIN_brandx"),
                    new SimpleGrantedAuthority("DOMAIN_brandy")))).isNull();              // injection => null
            assertThat(Roles.domainOf((List<SimpleGrantedAuthority>) null)).isNull();
        }

        @Test
        void domainOfNames_failsClosedOnZeroOrMany() {
            assertThat(Roles.domainOfNames(List.of())).isNull();                          // zero
            assertThat(Roles.domainOfNames(List.of("DOMAIN_brandx"))).isEqualTo("brandx");// exactly one
            assertThat(Roles.domainOfNames(List.of("DOMAIN_brandx", "DOMAIN_brandy"))).isNull();
            assertThat(Roles.domainOfNames(null)).isNull();
        }
    }

    @Nested
    class MfaSatisfiedFreshness {

        @Test
        void freshStamp_isSatisfied_withinWindow() {
            long now = 1_000_000L;
            Jwt jwt = base().claim(Roles.MFA_SATISFIED_AT_CLAIM, String.valueOf(now - 1_000L)).build();
            assertThat(Roles.isMfaSatisfied(jwt, now, 600_000L)).isTrue();
        }

        @Test
        void staleStamp_isRejected() {
            long now = 1_000_000L;
            Jwt jwt = base().claim(Roles.MFA_SATISFIED_AT_CLAIM, String.valueOf(now - 700_000L)).build();
            assertThat(Roles.isMfaSatisfied(jwt, now, 600_000L)).isFalse();
        }

        @Test
        void futureStamp_isRejected_clockSkewDefense() {
            long now = 1_000_000L;
            Jwt jwt = base().claim(Roles.MFA_SATISFIED_AT_CLAIM, String.valueOf(now + 5_000L)).build();
            assertThat(Roles.isMfaSatisfied(jwt, now, 600_000L)).isFalse();
        }

        @Test
        void missingOrMalformed_isRejected_neverThrows() {
            long now = 1_000_000L;
            assertThat(Roles.isMfaSatisfied(base().build(), now, 600_000L)).isFalse();         // absent
            assertThat(Roles.isMfaSatisfied(base().claim(Roles.MFA_SATISFIED_AT_CLAIM, "abc").build(), now, 600_000L)).isFalse();
            assertThat(Roles.isMfaSatisfied(base().claim(Roles.MFA_SATISFIED_AT_CLAIM, "  ").build(), now, 600_000L)).isFalse();
            assertThat(Roles.isMfaSatisfied(base().claim(Roles.MFA_SATISFIED_AT_CLAIM, "0").build(), now, 600_000L)).isFalse();
            assertThat(Roles.isMfaSatisfied(null, now, 600_000L)).isFalse();
        }
    }
}

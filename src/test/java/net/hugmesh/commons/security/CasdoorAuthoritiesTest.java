package net.hugmesh.commons.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security-critical unit test for the canonical {@link CasdoorAuthorities} converter:
 * roles-claim -&gt; {@code ROLE_<UPPER>}; {@code isAdmin} -&gt; {@code ROLE_ADMIN};
 * {@code DOMAIN_<x>} from the validated issuer ONLY; the RESERVED-PREFIX guard drops
 * forged {@code ROLE_}/{@code DOMAIN_}/{@code MFA_SATISFIED} permission strings; and
 * the MFA marker is derived only from a fresh stamp when MFA is enabled.
 */
class CasdoorAuthoritiesTest {

    private static final DomainRegistry SINGLE = new DomainRegistry("", "");
    private static final DomainRegistry MULTI =
            new DomainRegistry("", "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static Jwt.Builder base() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u");
    }

    private static List<String> names(List<GrantedAuthority> as) {
        return as.stream().map(GrantedAuthority::getAuthority).toList();
    }

    @Nested
    class RolesAndDomainMapping {

        @Test
        void everyTokenFloorsToRoleUser_andOneDomain() {
            List<String> a = names(CasdoorAuthorities.authorities(base().build(), SINGLE));
            assertThat(a).contains("ROLE_USER", "DOMAIN_default");
        }

        @Test
        void rolesClaim_becomesRolePrefixedUpper() {
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim("roles", List.of("admin", "mod")).build(), SINGLE));
            assertThat(a).contains("ROLE_ADMIN", "ROLE_MOD");
        }

        @Test
        void alreadyPrefixedRoles_canonicalizeToSinglePrefix() {
            // The seeded Casdoor roles are literally NAMED ROLE_ADMIN/ROLE_FORUM, so
            // the claim arrives pre-prefixed. Blind prefixing minted ROLE_ROLE_ADMIN
            // and every hasRole() answered 403 across the pure-resource-server BFFs.
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim("roles", List.of("ROLE_ADMIN", "role_forum")).build(), SINGLE));
            assertThat(a).contains("ROLE_ADMIN", "ROLE_FORUM");
            assertThat(a).doesNotContain("ROLE_ROLE_ADMIN", "ROLE_ROLE_FORUM");
        }

        @Test
        void reservedPrefixSmugglingStaysInert_evenViaRolePrefix() {
            // SECURITY: canonicalization must not open a reserved-prefix escape.
            // "DOMAIN_x" and "ROLE_DOMAIN_x" both land as the harmless ROLE_DOMAIN_X —
            // an ordinary role, not a DOMAIN_* tenant authority.
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim("roles", List.of("DOMAIN_x", "ROLE_DOMAIN_x", "ROLE_")).build(), SINGLE));
            assertThat(a).contains("ROLE_DOMAIN_X");
            // The converter's own issuer-derived tenant authority (DOMAIN_default for
            // the SINGLE registry) is legitimate — assert the SMUGGLED value never
            // appears as a bare tenant authority, not that no DOMAIN_* exists at all.
            assertThat(a).doesNotContain("DOMAIN_X", "DOMAIN_x");
            // a bare/blank "ROLE_" entry is dropped, not turned into "ROLE_"
            assertThat(a).doesNotContain("ROLE_");
        }

        @Test
        void legacyIsAdminBoolean_becomesRoleAdmin() {
            List<String> a = names(CasdoorAuthorities.authorities(base().claim("isAdmin", true).build(), SINGLE));
            assertThat(a).contains("ROLE_ADMIN");
        }

        @Test
        void domainComesFromValidatedIssuer() {
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().issuer("https://idp.brandx.example").build(), MULTI));
            assertThat(a).contains("DOMAIN_brandx").doesNotContain("DOMAIN_brandy", "DOMAIN_default");
        }

        @Test
        void plainPermissions_passThroughVerbatim() {
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim("permissions", List.of("federation:read", "cards:write")).build(), SINGLE));
            assertThat(a).contains("federation:read", "cards:write");
        }
    }

    @Nested
    class ReservedPrefixInjectionDefense {

        @Test
        void forgedRolePermission_isDropped() {
            // A brand-X token can't escalate to superadmin via a permission string.
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim("permissions", List.of("ROLE_SUPERADMIN")).build(), SINGLE));
            assertThat(a).doesNotContain("ROLE_SUPERADMIN");
        }

        @Test
        void forgedDomainPermission_isDropped_noCrossTenant() {
            // permissions:["DOMAIN_brandy"] must NOT inject a second tenant scope.
            List<GrantedAuthority> as = CasdoorAuthorities.authorities(
                    base().issuer("https://idp.brandx.example")
                            .claim("permissions", List.of("DOMAIN_brandy")).build(), MULTI);
            List<String> domains = names(as).stream().filter(s -> s.startsWith("DOMAIN_")).toList();
            assertThat(domains).containsExactly("DOMAIN_brandx");   // exactly one, the issuer's
        }

        @Test
        void forgedMfaPermission_isDropped() {
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim("permissions", List.of("MFA_SATISFIED")).build(), SINGLE));
            assertThat(a).doesNotContain("MFA_SATISFIED");
        }

        @Test
        void reservedGuardIsCaseAndWhitespaceInsensitive() {
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim("permissions", List.of("  role_superadmin  ", "domain_brandy")).build(), SINGLE));
            assertThat(a).noneMatch(s -> s.toUpperCase().contains("SUPERADMIN"))
                    .doesNotContain("domain_brandy");
        }
    }

    @Nested
    class MfaMarkerDerivation {

        @Test
        void mfaDisabled_neverEmitsMarker_evenWithFreshStamp() {
            long now = 1_000_000L;
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim(Roles.MFA_SATISFIED_AT_CLAIM, String.valueOf(now - 1000)).build(),
                    SINGLE, CasdoorAuthorities.MfaConfig.DISABLED, now));
            assertThat(a).doesNotContain("MFA_SATISFIED");
        }

        @Test
        void mfaEnabled_freshStamp_emitsMarker() {
            long now = 1_000_000L;
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim(Roles.MFA_SATISFIED_AT_CLAIM, String.valueOf(now - 1000)).build(),
                    SINGLE, new CasdoorAuthorities.MfaConfig(true, 600_000L), now));
            assertThat(a).contains("MFA_SATISFIED");
        }

        @Test
        void mfaEnabled_staleStamp_omitsMarker() {
            long now = 1_000_000L;
            List<String> a = names(CasdoorAuthorities.authorities(
                    base().claim(Roles.MFA_SATISFIED_AT_CLAIM, String.valueOf(now - 700_000L)).build(),
                    SINGLE, new CasdoorAuthorities.MfaConfig(true, 600_000L), now));
            assertThat(a).doesNotContain("MFA_SATISFIED");
        }
    }

    @Test
    void roleObjectShape_isSupported() {
        List<String> a = names(CasdoorAuthorities.authorities(
                base().claim("roles", List.of(Map.of("name", "admin"))).build(), SINGLE));
        assertThat(a).contains("ROLE_ADMIN");
    }
}

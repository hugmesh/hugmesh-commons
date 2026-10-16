package net.hugmesh.commons.security;

import net.hugmesh.commons.security.MfaPolicy.Decision;
import net.hugmesh.commons.security.MfaPolicy.Requirement;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

/**
 * Unit test for {@link MfaPolicy}: the default policy asks for nothing, the
 * strictest role wins, and a required principal is allowed only by a fresh
 * {@code mfa_satisfied_at} stamp (stale, future, malformed and forged inputs
 * are challenged).
 */
class MfaPolicyTest {

    private static final long NOW = 1_750_000_000_000L;
    private static final long WINDOW = 600_000L;

    private static Jwt.Builder base() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u");
    }

    private static Jwt jwt(final List<String> roles, final Object stamp) {
        Jwt.Builder b = base().claim("roles", roles);
        if (stamp != null) {
            b.claim(Roles.MFA_SATISFIED_AT_CLAIM, stamp);
        }
        return b.build();
    }

    private static MfaPolicy adminRequired() {
        return MfaPolicy.of(Map.of(RoleName.ADMIN, Requirement.REQUIRED));
    }

    @Test
    void defaultPolicy_allowsAnAuthenticatedPrincipal_withoutAStamp() {
        assertThat(MfaPolicy.DEFAULT.decide(jwt(List.of("admin"), null), NOW, WINDOW))
                .isEqualTo(Decision.ALLOW);
        assertThat(MfaPolicy.DEFAULT.decide(jwt(List.of("superadmin"), null), NOW, WINDOW))
                .isEqualTo(Decision.ALLOW);
        assertThat(MfaPolicy.DEFAULT.requirementFor(jwt(List.of("admin"), null)))
                .isEqualTo(Requirement.OPTIONAL);
    }

    @Test
    void requiredRole_withoutStamp_isChallenged() {
        assertThat(adminRequired().decide(jwt(List.of("admin"), null), NOW, WINDOW))
                .isEqualTo(Decision.CHALLENGE);
    }

    @Test
    void requiredRole_withFreshStamp_isAllowed() {
        assertThat(adminRequired().decide(jwt(List.of("admin"), String.valueOf(NOW - 1_000)), NOW, WINDOW))
                .isEqualTo(Decision.ALLOW);
    }

    @Test
    void requiredRole_windowEdge_isInclusive() {
        assertThat(adminRequired().decide(jwt(List.of("admin"), String.valueOf(NOW - WINDOW)), NOW, WINDOW))
                .isEqualTo(Decision.ALLOW);
        assertThat(adminRequired().decide(jwt(List.of("admin"), String.valueOf(NOW - WINDOW - 1)), NOW, WINDOW))
                .isEqualTo(Decision.CHALLENGE);
    }

    @Test
    void requiredRole_futureStamp_isChallenged() {
        assertThat(adminRequired().decide(jwt(List.of("admin"), String.valueOf(NOW + 1)), NOW, WINDOW))
                .isEqualTo(Decision.CHALLENGE);
        assertThat(adminRequired().decide(jwt(List.of("admin"), String.valueOf(Long.MAX_VALUE)), NOW, WINDOW))
                .isEqualTo(Decision.CHALLENGE);
    }

    @Test
    void requiredRole_malformedStamp_isChallenged() {
        for (Object bad : new Object[] {"", "  ", "not-a-number", "MFA_SATISFIED", "0", "-5"}) {
            assertThat(adminRequired().decide(jwt(List.of("admin"), bad), NOW, WINDOW))
                    .as("stamp %s", bad).isEqualTo(Decision.CHALLENGE);
        }
    }

    @Test
    void requiredRole_nonPositiveStamp_isChallenged_evenWithAnUnboundedWindow() {
        for (Object bad : new Object[] {"0", "-5"}) {
            assertThat(adminRequired().decide(jwt(List.of("admin"), bad), NOW, Long.MAX_VALUE))
                    .as("stamp %s", bad).isEqualTo(Decision.CHALLENGE);
        }
    }

    @Test
    void requiredRole_forgedMarkerInPermissions_isChallenged() {
        Jwt forged = base().claim("roles", List.of("admin"))
                .claim("permissions", List.of("MFA_SATISFIED")).build();
        assertThat(adminRequired().decide(forged, NOW, WINDOW)).isEqualTo(Decision.CHALLENGE);
    }

    @Test
    void stepUp_shorterWindowChallengesAStampThatPassesTheSessionWindow() {
        Jwt j = jwt(List.of("admin"), String.valueOf(NOW - 300_000));
        assertThat(adminRequired().decide(j, NOW, WINDOW)).isEqualTo(Decision.ALLOW);
        assertThat(adminRequired().decide(j, NOW, 60_000L)).isEqualTo(Decision.CHALLENGE);
    }

    @Test
    void optionalRole_isAllowedWithoutAStamp() {
        assertThat(adminRequired().decide(jwt(List.of("mod"), null), NOW, WINDOW))
                .isEqualTo(Decision.ALLOW);
        assertThat(adminRequired().requirementFor(jwt(List.of("mod"), null)))
                .isEqualTo(Requirement.OPTIONAL);
    }

    @Test
    void explicitOptional_isNotRequired() {
        MfaPolicy p = MfaPolicy.of(Map.of(RoleName.ADMIN, Requirement.OPTIONAL));
        assertThat(p.decide(jwt(List.of("admin"), null), NOW, WINDOW)).isEqualTo(Decision.ALLOW);
    }

    @Test
    void strictestRoleWins() {
        MfaPolicy p = MfaPolicy.of(Map.of(
                RoleName.MOD, Requirement.OPTIONAL, RoleName.ADMIN, Requirement.REQUIRED));
        assertThat(p.requirementFor(jwt(List.of("mod", "admin"), null))).isEqualTo(Requirement.REQUIRED);
        assertThat(p.requirementFor(jwt(List.of("admin", "mod"), null))).isEqualTo(Requirement.REQUIRED);
    }

    @Test
    void userEntryAppliesToEveryPrincipal_includingOneWithNoRoles() {
        MfaPolicy p = MfaPolicy.of(Map.of(RoleName.USER, Requirement.REQUIRED));
        assertThat(p.requirementFor(jwt(List.of("mod"), null))).isEqualTo(Requirement.REQUIRED);
        assertThat(p.requirementFor(base().build())).isEqualTo(Requirement.REQUIRED);
    }

    @Test
    void legacyIsAdminBoolean_isTheAdminRole() {
        Jwt legacy = base().claim("isAdmin", true).build();
        assertThat(adminRequired().requirementFor(legacy)).isEqualTo(Requirement.REQUIRED);
        assertThat(adminRequired().decide(legacy, NOW, WINDOW)).isEqualTo(Decision.CHALLENGE);
        Jwt fresh = base().claim("isAdmin", true)
                .claim(Roles.MFA_SATISFIED_AT_CLAIM, String.valueOf(NOW - 1_000)).build();
        assertThat(adminRequired().decide(fresh, NOW, WINDOW)).isEqualTo(Decision.ALLOW);
    }

    @Test
    void roleNames_matchCaseInsensitively() {
        assertThat(adminRequired().requirementFor(jwt(List.of("Admin"), null))).isEqualTo(Requirement.REQUIRED);
    }

    @Test
    void everySuperadminSpelling_isTheSuperadminRole() {
        MfaPolicy p = MfaPolicy.of(Map.of(RoleName.SUPERADMIN, Requirement.REQUIRED));
        for (String spelling : List.of("superadmin", "super-admin", "super_admin")) {
            assertThat(p.requirementFor(jwt(List.of(spelling), null)))
                    .as(spelling).isEqualTo(Requirement.REQUIRED);
        }
    }

    @Test
    void roleOutsideTheClosedSet_isIgnored() {
        assertThat(adminRequired().requirementFor(jwt(List.of("matrix", "image-builder"), null)))
                .isEqualTo(Requirement.OPTIONAL);
    }

    // The platform's seeded Casdoor roles are literally named ROLE_ADMIN etc., so
    // real tokens arrive prefixed (see CasdoorAuthorities).

    private static Jwt withRolesClaim(final Object roles) {
        return base().claim("roles", roles).build();
    }

    @Test
    void platformShape_prefixedRoleNames_areTheBaseRole() {
        for (String spelling : List.of("ROLE_ADMIN", "role_admin", " ROLE_ADMIN ", "ROLE_ ADMIN")) {
            Jwt token = withRolesClaim(List.of(spelling));
            assertThat(adminRequired().requirementFor(token))
                    .as(spelling).isEqualTo(Requirement.REQUIRED);
            assertThat(adminRequired().decide(token, NOW, WINDOW))
                    .as(spelling).isEqualTo(Decision.CHALLENGE);
        }
    }

    @Test
    void platformShape_objectFormWithPrefixedName_isTheBaseRole() {
        Jwt token = withRolesClaim(List.of(Map.of("name", "ROLE_ADMIN", "displayName", "Admin")));
        assertThat(adminRequired().requirementFor(token)).isEqualTo(Requirement.REQUIRED);
    }

    @Test
    void platformShape_prefixedSuperadminSpellings_areTheSuperadminRole() {
        MfaPolicy p = MfaPolicy.of(Map.of(RoleName.SUPERADMIN, Requirement.REQUIRED));
        for (String spelling : List.of("ROLE_SUPERADMIN", "ROLE_SUPER-ADMIN", "ROLE_SUPER_ADMIN")) {
            assertThat(p.requirementFor(withRolesClaim(List.of(spelling))))
                    .as(spelling).isEqualTo(Requirement.REQUIRED);
        }
    }

    @Test
    void platformShape_prefixedModRole_isTheModRole() {
        MfaPolicy p = MfaPolicy.of(Map.of(RoleName.MOD, Requirement.REQUIRED));
        assertThat(p.requirementFor(withRolesClaim(List.of("ROLE_MOD")))).isEqualTo(Requirement.REQUIRED);
    }

    @Test
    void platformShape_prefixedRequiredRole_withFreshStamp_isAllowed() {
        Jwt fresh = base().claim("roles", List.of("ROLE_ADMIN"))
                .claim(Roles.MFA_SATISFIED_AT_CLAIM, String.valueOf(NOW - 1_000)).build();
        assertThat(adminRequired().decide(fresh, NOW, WINDOW)).isEqualTo(Decision.ALLOW);
    }

    @Test
    void anyRoleTheConverterTurnsIntoAnAdminAuthority_isRequiredUnderAnAdminPolicy() {
        MfaPolicy p = MfaPolicy.of(Map.of(
                RoleName.ADMIN, Requirement.REQUIRED, RoleName.SUPERADMIN, Requirement.REQUIRED));
        for (String spelling : List.of("ROLE_ADMIN", "role_admin", " ROLE_ADMIN ", "ROLE_ ADMIN", "admin",
                "ROLE_SUPERADMIN", "ROLE_SUPER-ADMIN", "ROLE_SUPER_ADMIN", "super-admin", "SUPER_ADMIN")) {
            Jwt token = withRolesClaim(List.of(spelling));
            boolean privileged = CasdoorAuthorities.authorities(token, null).stream()
                    .map(a -> a.getAuthority())
                    .anyMatch(a -> a.equals("ROLE_ADMIN") || a.equals("ROLE_SUPERADMIN")
                            || a.equals("ROLE_SUPER-ADMIN") || a.equals("ROLE_SUPER_ADMIN"));
            assertThat(privileged).as("converter grants a privileged authority for " + spelling).isTrue();
            assertThat(p.requirementFor(token)).as(spelling).isEqualTo(Requirement.REQUIRED);
        }
    }

    @Test
    void wellFormedAppRole_withPrefix_isIgnored() {
        assertThat(adminRequired().requirementFor(withRolesClaim(List.of("ROLE_FORUM", "ROLE_matrix"))))
                .isEqualTo(Requirement.OPTIONAL);
    }

    @Test
    void doublePrefix_isNotTheBaseRole() {
        // One strip, one re-prefix: the converter mints ROLE_ROLE_ADMIN, an ordinary role.
        assertThat(adminRequired().requirementFor(withRolesClaim(List.of("ROLE_ROLE_ADMIN"))))
                .isEqualTo(Requirement.OPTIONAL);
    }

    @Test
    void unreadableRolesClaim_failsClosed_whenThePolicyRequiresAnything() {
        List<Object> unreadable = new java.util.ArrayList<>();
        unreadable.add(null);
        for (Object claim : List.of("ROLE_ADMIN", Map.of("name", "ROLE_ADMIN"), 7,
                unreadable, List.of(42), List.of(Map.of("displayName", "no name")),
                List.of(Map.of("name", 7)), List.of("ROLE_"), List.of("role_ "),
                List.of("matrix", 42))) {
            Jwt token = withRolesClaim(claim);
            assertThat(adminRequired().requirementFor(token))
                    .as(String.valueOf(claim)).isEqualTo(Requirement.REQUIRED);
            assertThat(adminRequired().decide(token, NOW, WINDOW))
                    .as(String.valueOf(claim)).isEqualTo(Decision.CHALLENGE);
            assertThat(MfaPolicy.DEFAULT.requirementFor(token))
                    .as("default " + claim).isEqualTo(Requirement.OPTIONAL);
        }
    }

    @Test
    void blankRoleEntries_areHarmless() {
        assertThat(adminRequired().requirementFor(
                withRolesClaim(List.of("", "  ", Map.of("name", " ")))))
                .isEqualTo(Requirement.OPTIONAL);
    }

    @Test
    void nullJwt_isRequiredAndChallenged_evenUnderTheDefaultPolicy() {
        assertThat(MfaPolicy.DEFAULT.requirementFor(null)).isEqualTo(Requirement.REQUIRED);
        assertThat(MfaPolicy.DEFAULT.decide(null, NOW, WINDOW)).isEqualTo(Decision.CHALLENGE);
    }

    @Test
    void of_copiesTheMap() {
        Map<RoleName, Requirement> m = new HashMap<>();
        MfaPolicy p = MfaPolicy.of(m);
        m.put(RoleName.ADMIN, Requirement.REQUIRED);
        assertThat(p.requirementFor(jwt(List.of("admin"), null))).isEqualTo(Requirement.OPTIONAL);
    }

    @Test
    void of_rejectsNulls() {
        assertThatNullPointerException().isThrownBy(() -> MfaPolicy.of(null));
        Map<RoleName, Requirement> nullValue = new HashMap<>();
        nullValue.put(RoleName.ADMIN, null);
        assertThatNullPointerException().isThrownBy(() -> MfaPolicy.of(nullValue));
        Map<RoleName, Requirement> nullKey = new HashMap<>();
        nullKey.put(null, Requirement.REQUIRED);
        assertThatNullPointerException().isThrownBy(() -> MfaPolicy.of(nullKey));
    }
}

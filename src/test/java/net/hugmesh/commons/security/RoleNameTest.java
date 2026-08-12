package net.hugmesh.commons.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit test for {@link RoleName} — the CLOSED base-role-name enum. The bar is
 * adversarial: a drift in the wire form ({@link RoleName#value()} / JSON) is a
 * privilege/authZ bug (it would silently rename a Casdoor role grant), so every
 * constant's value is pinned to the exact prior String literal and the JSON
 * round-trips byte-identically.
 */
class RoleNameTest {

    private final ObjectMapper json = new ObjectMapper();

    @Nested
    class WireForm {

        /** The four base roles map to EXACTLY the prior lowercase literals — the
         *  Casdoor/usage/JSON contract. Any change here is an authZ wire-drift bug. */
        @Test
        void value_isExactPriorLowercaseLiteral() {
            assertThat(RoleName.USER.value()).isEqualTo("user");
            assertThat(RoleName.MOD.value()).isEqualTo("mod");
            assertThat(RoleName.ADMIN.value()).isEqualTo("admin");
            assertThat(RoleName.SUPERADMIN.value()).isEqualTo("superadmin");
        }

        /** toString() is the wire value, NOT the upper-case constant name — so any
         *  accidental String concatenation keeps the lowercase token. */
        @Test
        void toString_isWireValueNotConstantName() {
            assertThat(RoleName.ADMIN.toString()).isEqualTo("admin");
            assertThat(RoleName.SUPERADMIN.toString()).isEqualTo("superadmin");
            assertThat(String.valueOf(RoleName.MOD)).isEqualTo("mod");
        }

        /** The CLOSED set is exactly these four, in this order — guards against an
         *  accidental fifth base role widening the closed domain. */
        @Test
        void closedSet_isExactlyTheFourBaseRoles() {
            assertThat(List.of(RoleName.values()))
                    .extracting(RoleName::value)
                    .containsExactly("user", "mod", "admin", "superadmin");
        }
    }

    @Nested
    class JsonRoundTrip {

        /** Each constant serializes (via @JsonValue) to its exact lowercase token. */
        @Test
        void serializes_toLowercaseToken() throws Exception {
            assertThat(json.writeValueAsString(RoleName.USER)).isEqualTo("\"user\"");
            assertThat(json.writeValueAsString(RoleName.MOD)).isEqualTo("\"mod\"");
            assertThat(json.writeValueAsString(RoleName.ADMIN)).isEqualTo("\"admin\"");
            assertThat(json.writeValueAsString(RoleName.SUPERADMIN)).isEqualTo("\"superadmin\"");
        }

        /** A lowercase token deserializes (via @JsonCreator) back to the same
         *  constant — full round-trip with zero value change. */
        @Test
        void deserializes_lowercaseToken_roundTrips() throws Exception {
            for (RoleName r : RoleName.values()) {
                String wire = json.writeValueAsString(r);
                assertThat(json.readValue(wire, RoleName.class)).isEqualTo(r);
            }
        }

        /** A LIST of the enum serializes to the exact lowercase JSON array the
         *  Casdoor/usage call sites previously produced from List.of("user","admin"). */
        @Test
        void list_serializes_toPriorLiteralArray() throws Exception {
            assertThat(json.writeValueAsString(List.of(RoleName.USER, RoleName.ADMIN)))
                    .isEqualTo("[\"user\",\"admin\"]");
        }
    }

    @Nested
    class FromWire {

        @Test
        void resolvesEachKnownToken_caseInsensitiveAndTrimmed() {
            assertThat(RoleName.fromWire("user")).isEqualTo(RoleName.USER);
            assertThat(RoleName.fromWire("ADMIN")).isEqualTo(RoleName.ADMIN);
            assertThat(RoleName.fromWire("  superadmin  ")).isEqualTo(RoleName.SUPERADMIN);
            assertThat(RoleName.fromWire("Mod")).isEqualTo(RoleName.MOD);
        }

        /** FAIL-CLOSED: null / blank / unknown / dynamic tokens are NOT a base role
         *  and return null (never silently widen the closed set). */
        @Test
        void failsClosed_onUnknownOrDynamicOrBlank() {
            assertThat(RoleName.fromWire(null)).isNull();
            assertThat(RoleName.fromWire("")).isNull();
            assertThat(RoleName.fromWire("   ")).isNull();
            // dynamic / service / capability roles MUST NOT be absorbed as base roles
            assertThat(RoleName.fromWire("matrix")).isNull();
            assertThat(RoleName.fromWire("mastodon")).isNull();
            assertThat(RoleName.fromWire("games")).isNull();
            assertThat(RoleName.fromWire("image-builder")).isNull();
            // per-domain dynamic scope strings stay untouched (not base roles)
            assertThat(RoleName.fromWire("DOMAIN_brandx")).isNull();
            assertThat(RoleName.fromWire("ROLE_ADMIN")).isNull(); // authority form, not a token
        }

        /** Jackson deserialization of an unknown token also fails closed to null. */
        @Test
        void jsonDeserialize_unknownToken_isNull() throws Exception {
            assertThat(json.readValue("\"matrix\"", RoleName.class)).isNull();
            assertThat(json.readValue("\"DOMAIN_brandx\"", RoleName.class)).isNull();
        }

        @Test
        void isBaseRole_matchesClosedSetOnly() {
            assertThat(RoleName.isBaseRole("admin")).isTrue();
            assertThat(RoleName.isBaseRole("SUPERADMIN")).isTrue();
            assertThat(RoleName.isBaseRole("matrix")).isFalse();
            assertThat(RoleName.isBaseRole(null)).isFalse();
        }

        @Test
        void require_throwsOnNonBaseRole() {
            assertThat(RoleName.require("admin")).isEqualTo(RoleName.ADMIN);
            assertThatThrownBy(() -> RoleName.require("matrix"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("matrix");
        }
    }

    @Nested
    class CallSiteEquivalence {

        /** Proves the planned admin-bff replacement produces argument lists IDENTICAL
         *  to the prior String literals: List.of("user","admin") and List.of("admin")
         *  etc. equal the mapped enum values. This is the "no argument change" proof. */
        @Test
        void mappedValues_equalPriorLiteralArguments() {
            assertThat(List.of(RoleName.USER.value(), RoleName.ADMIN.value()))
                    .isEqualTo(List.of("user", "admin"));
            assertThat(List.of(RoleName.USER.value()))
                    .isEqualTo(List.of("user"));
            assertThat(List.of(RoleName.ADMIN.value()))
                    .isEqualTo(List.of("admin"));
            assertThat(List.of(RoleName.ADMIN.value(), RoleName.SUPERADMIN.value(), RoleName.MOD.value()))
                    .isEqualTo(List.of("admin", "superadmin", "mod"));
        }

        /** The usage-analytics comparison key (UsageService compares roles against the
         *  literal "admin") is preserved by RoleName.ADMIN.value(). */
        @Test
        void usageAdminKey_preserved() {
            assertThat(List.of(RoleName.ADMIN.value()).contains("admin")).isTrue();
            assertThat(List.of(RoleName.USER.value()).contains("admin")).isFalse();
        }
    }
}

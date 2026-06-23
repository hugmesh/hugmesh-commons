package systems.snapdragon.commons.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The CLOSED set of Snapdragon <em>base</em> role NAMES — the lowercase, on-the-wire
 * Casdoor role tokens {@code user} / {@code mod} / {@code admin} / {@code superadmin}.
 *
 * <p>This enum is the typed, single-source-of-truth form of the raw {@code "user"} /
 * {@code "mod"} / {@code "admin"} / {@code "superadmin"} string literals that were
 * scattered across the BFFs as arguments to the Casdoor role-assignment client
 * ({@code ensureUser(..., List<String> roles)} upper-cases each token into the Casdoor
 * {@code ROLE_<UPPER>} role) and to the usage-analytics
 * {@code UsageService.record(actor, List<String> roles, action)} (which compares the
 * list against {@code "admin"}). It applies Convention&nbsp;C ("a fixed, closed set of
 * String constants becomes an enum") to the highest-value, security-relevant case.
 *
 * <p><b>WIRE CONTRACT — do not change the serialized value.</b> The {@link #value()}
 * returned here (and emitted via {@link JsonValue}) is the IDENTICAL lowercase string
 * that previously appeared as a literal. It is a CONTRACT with:
 * <ul>
 *   <li><b>Casdoor</b> — {@code CasdoorAdminClient.ensureUser(...)} upper-cases each
 *       token (e.g. {@code "admin"} &rarr; the Casdoor role {@code ADMIN}/{@code ROLE_ADMIN}).
 *       The token MUST stay lowercase so that upper-casing reproduces the existing
 *       Casdoor role name byte-for-byte.</li>
 *   <li>the <b>gateway / {@link CasdoorAuthorities} converter</b> — which derives the
 *       Spring authority {@code ROLE_<UPPER>} from the same role NAME.</li>
 *   <li><b>JSON / DB</b> — wherever these tokens are serialized.</li>
 * </ul>
 * Changing a {@code value()} (e.g. to upper-case) is a privilege/authZ bug: it would
 * silently rename or drop a Casdoor role grant. The enum CONSTANT names are upper-case
 * (Java convention); the wire value is the lower-case {@link #value()} — never confuse
 * the two.
 *
 * <p><b>Scope — base roles ONLY (a genuinely closed set).</b> This enum deliberately
 * does NOT model:
 * <ul>
 *   <li>per-domain DYNAMIC tenant scopes ({@code DOMAIN_<brand>}) — an OPEN set keyed on
 *       the validated issuer; see {@link CasdoorAuthorities} / {@link DomainRegistry}.</li>
 *   <li>service / capability roles ({@code matrix}, {@code mastodon}, {@code games},
 *       {@code image-builder}, the {@code *-domainlocked} / {@code *-external-client}
 *       variants, …) — those are an extensible set granted independently and MUST stay
 *       free-form String.</li>
 *   <li>the reserved authority PREFIXES ({@code ROLE_} / {@code DOMAIN_} /
 *       {@code MFA_SATISFIED}) — handled by {@link Roles} / {@link CasdoorAuthorities}.</li>
 * </ul>
 * It COMPLEMENTS {@link Roles} (which operates on the {@code ROLE_}-prefixed AUTHORITY
 * form): {@code Roles} answers "does this principal hold role X / which domain"; this
 * enum names the lowercase role TOKENS handed to Casdoor / usage at the write boundary.
 */
public enum RoleName {

    /** The authenticated-user floor role. Wire token {@code "user"}. */
    USER("user"),

    /** The moderator role. Wire token {@code "mod"}. */
    MOD("mod"),

    /** The per-domain administrator role. Wire token {@code "admin"}. */
    ADMIN("admin"),

    /** The cross-domain infra super-role. Wire token {@code "superadmin"}. */
    SUPERADMIN("superadmin");

    private final String value;

    RoleName(String value) {
        this.value = value;
    }

    /**
     * The exact lowercase on-the-wire role token (e.g. {@code "admin"}). This is what
     * Casdoor / usage / JSON have always seen; it is emitted as the Jackson
     * serialization of this enum via {@link JsonValue}.
     */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Resolve a wire token to its {@link RoleName}, or {@code null} when the token is
     * not one of the four CLOSED base roles. FAIL-CLOSED and tolerant: a {@code null} /
     * blank / unknown token (e.g. a dynamic {@code matrix} / {@code DOMAIN_*} string) is
     * NOT a base role and returns {@code null} rather than throwing — the caller keeps
     * the original String for the open-set cases. Matching is case-insensitive and
     * whitespace-trimmed on READ only; the canonical stored/emitted form is always the
     * lowercase {@link #value()}.
     *
     * <p>Used as the Jackson {@link JsonCreator} so deserializing an unknown role token
     * yields {@code null} (fail-closed) instead of an enum that silently widens the
     * closed set.
     */
    @JsonCreator
    public static RoleName fromWire(String token) {
        if (token == null) return null;
        String t = token.trim();
        if (t.isEmpty()) return null;
        for (RoleName r : values()) {
            if (r.value.equalsIgnoreCase(t)) return r;
        }
        return null;
    }

    /**
     * Strict variant of {@link #fromWire(String)}: resolve a token that the caller
     * ASSERTS is a base role, throwing {@link IllegalArgumentException} on anything
     * outside the closed set. Use where an unknown base-role token is a programming
     * error rather than an expected dynamic/open-set value.
     */
    public static RoleName require(String token) {
        RoleName r = fromWire(token);
        if (r == null) {
            throw new IllegalArgumentException("not a closed base role name: " + token);
        }
        return r;
    }

    /** True iff {@code token} is one of the four CLOSED base role names
     *  (case-insensitive, trimmed). A dynamic/service/domain token returns
     *  {@code false}. */
    public static boolean isBaseRole(String token) {
        return fromWire(token) != null;
    }

    /** The lowercase wire token — identical to {@link #value()}. Provided so callers
     *  that already hold a {@code RoleName} read naturally; never returns the
     *  upper-case constant name. */
    @Override
    public String toString() {
        return value;
    }
}

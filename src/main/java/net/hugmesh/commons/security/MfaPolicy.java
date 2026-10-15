package net.hugmesh.commons.security;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * Per-role second-factor requirement plus the step-up decision built on the
 * {@link Roles#MFA_SATISFIED_AT_CLAIM} stamp.
 *
 * <p>This is a decision primitive only. It enrols no factor and reads no
 * configuration: WebAuthn, TOTP and recovery codes belong to the services that
 * run the challenge, which write the stamp this class reads.
 *
 * <h2>Requirement</h2>
 *
 * <p>The policy maps a {@link RoleName} to a {@link Requirement}. A principal's
 * requirement is the strictest entry among the base roles it holds, plus the
 * {@link RoleName#USER} entry, because every authenticated principal floors to
 * {@code ROLE_USER}. A role with no entry is {@link Requirement#OPTIONAL}.
 * {@link #DEFAULT} has no entries, so for an authenticated principal (a non-null
 * JWT) it yields {@link Requirement#OPTIONAL} and {@link Decision#ALLOW}.
 *
 * <h2>Decision</h2>
 *
 * <p>{@link #decide(Jwt, long, long)} answers {@link Decision#ALLOW} when no
 * second factor is required, or when the stamp is fresh according to
 * {@link Roles#isMfaSatisfied(Jwt, long, long)}. Otherwise it answers
 * {@link Decision#CHALLENGE}. Only that stamp counts: a {@code permissions}
 * entry or authority named {@code MFA_SATISFIED} is not consulted. A privileged
 * operation asks for step-up by passing a shorter window than the session
 * default.
 *
 * <p>A {@code null} JWT is {@link Requirement#REQUIRED} and
 * {@link Decision#CHALLENGE}.
 */
public final class MfaPolicy {

    /** Whether a principal must hold a fresh second-factor stamp. */
    public enum Requirement {
        /** No second factor is asked for. */
        OPTIONAL,
        /** A fresh second-factor stamp is needed. */
        REQUIRED
    }

    /** The outcome of {@link #decide(Jwt, long, long)}. */
    public enum Decision {
        /** The request may proceed. */
        ALLOW,
        /** The caller must run a second-factor challenge first. */
        CHALLENGE
    }

    /** A policy with no entries: every principal is {@link Requirement#OPTIONAL}. */
    public static final MfaPolicy DEFAULT = new MfaPolicy(new EnumMap<>(RoleName.class));

    private final Map<RoleName, Requirement> byRole;

    private MfaPolicy(final EnumMap<RoleName, Requirement> entries) {
        this.byRole = entries;
    }

    /**
     * Builds a policy from the given entries. The map is copied; later changes
     * to it do not affect the policy.
     *
     * @param entries role to requirement; neither the map, a key nor a value
     *                may be {@code null}
     * @return the policy
     * @throws NullPointerException if the map, a key or a value is {@code null}
     */
    public static MfaPolicy of(final Map<RoleName, Requirement> entries) {
        Objects.requireNonNull(entries, "entries");
        EnumMap<RoleName, Requirement> copy = new EnumMap<>(RoleName.class);
        for (Map.Entry<RoleName, Requirement> e : entries.entrySet()) {
            copy.put(Objects.requireNonNull(e.getKey(), "role"),
                    Objects.requireNonNull(e.getValue(), "requirement"));
        }
        return new MfaPolicy(copy);
    }

    /**
     * The requirement that applies to the principal behind {@code jwt}: the
     * strictest entry among its base roles and {@link RoleName#USER}.
     * Every spelling of the super-role accepted by {@link Roles#isSuperadmin(Jwt)}
     * counts as {@link RoleName#SUPERADMIN}, and the legacy {@code isAdmin}
     * boolean accepted by {@link Roles#isAdmin(Jwt)} counts as
     * {@link RoleName#ADMIN}; role names outside the four base roles are
     * ignored.
     *
     * @param jwt the validated JWT; {@code null} yields
     *            {@link Requirement#REQUIRED}
     * @return the requirement
     */
    public Requirement requirementFor(final Jwt jwt) {
        if (jwt == null) {
            return Requirement.REQUIRED;
        }
        if (byRole.get(RoleName.USER) == Requirement.REQUIRED) {
            return Requirement.REQUIRED;
        }
        for (String name : Roles.fromJwt(jwt)) {
            RoleName role = RoleName.fromWire(name);
            if (role != null && byRole.get(role) == Requirement.REQUIRED) {
                return Requirement.REQUIRED;
            }
        }
        if (Roles.isSuperadmin(jwt)
                && byRole.get(RoleName.SUPERADMIN) == Requirement.REQUIRED) {
            return Requirement.REQUIRED;
        }
        if (Roles.isAdmin(jwt)
                && byRole.get(RoleName.ADMIN) == Requirement.REQUIRED) {
            return Requirement.REQUIRED;
        }
        return Requirement.OPTIONAL;
    }

    /**
     * Decides whether the request may proceed.
     *
     * @param jwt          the validated JWT; {@code null} yields
     *                     {@link Decision#CHALLENGE}
     * @param now          current epoch milliseconds, supplied by the caller
     * @param windowMillis the longest acceptable age of the stamp; pass a
     *                     shorter window than the session default to ask for
     *                     step-up
     * @return {@link Decision#ALLOW} when the principal needs no second factor
     *         or holds a fresh stamp, otherwise {@link Decision#CHALLENGE}
     */
    public Decision decide(final Jwt jwt, final long now, final long windowMillis) {
        if (requirementFor(jwt) == Requirement.OPTIONAL) {
            return Decision.ALLOW;
        }
        return Roles.isMfaSatisfied(jwt, now, windowMillis)
                ? Decision.ALLOW : Decision.CHALLENGE;
    }
}

package net.hugmesh.commons.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for the canonical instance-based {@link PrincipalDomain}: superadmin is
 * unscoped (carries a home domain but {@code scoped()==false}); a scoped principal is
 * pinned to its issuer-derived domain; an unresolvable / non-JWT principal fails
 * closed to {@link PrincipalDomain#NO_DOMAIN}.
 */
class PrincipalDomainTest {

    private static final DomainRegistry MULTI =
            new DomainRegistry("", "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static Jwt jwt(String issuer, List<String> roles) {
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600)).subject("u");
        if (issuer != null) b.issuer(issuer);
        if (roles != null) b.claim("roles", roles);
        return b.build();
    }

    private static Authentication auth(Jwt jwt) {
        return new UsernamePasswordAuthenticationToken(jwt, "n/a", List.of());
    }

    @Test
    void scopedPrincipal_isPinnedToIssuerDomain() {
        PrincipalDomain pd = PrincipalDomain.resolve(jwt("https://idp.brandx.example", List.of("admin")), MULTI);
        assertThat(pd.domain()).isEqualTo("brandx");
        assertThat(pd.superadmin()).isFalse();
        assertThat(pd.scoped()).isTrue();
    }

    @Test
    void superadmin_isUnscoped_butKeepsHomeDomain() {
        PrincipalDomain pd = PrincipalDomain.resolve(jwt("https://idp.brandx.example", List.of("superadmin")), MULTI);
        assertThat(pd.superadmin()).isTrue();
        assertThat(pd.scoped()).isFalse();
        assertThat(pd.domain()).isEqualTo("brandx");   // home brand for rows it writes
    }

    @Test
    void unknownIssuer_failsClosed_noDomain() {
        PrincipalDomain pd = PrincipalDomain.resolve(jwt("https://evil.example", List.of("admin")), MULTI);
        assertThat(pd.domain()).isEqualTo(PrincipalDomain.NO_DOMAIN);
        assertThat(pd.superadmin()).isFalse();
    }

    @Test
    void nonJwtOrNullAuthentication_failsClosed() {
        assertThat(PrincipalDomain.of(null, MULTI).domain()).isEqualTo(PrincipalDomain.NO_DOMAIN);
        Authentication notJwt = new UsernamePasswordAuthenticationToken("plain-principal", "n/a", List.of());
        assertThat(PrincipalDomain.of(notJwt, MULTI).domain()).isEqualTo(PrincipalDomain.NO_DOMAIN);
        assertThat(PrincipalDomain.resolve(null, MULTI).domain()).isEqualTo(PrincipalDomain.NO_DOMAIN);
    }

    @Test
    void ofAuthentication_resolvesJwtPrincipal() {
        PrincipalDomain pd = PrincipalDomain.of(auth(jwt("https://idp.brandy.example", List.of("user"))), MULTI);
        assertThat(pd.domain()).isEqualTo("brandy");
        assertThat(pd.scoped()).isTrue();
    }

    @Test
    void factoryHelpers_forDomainAndSuperadminFor() {
        assertThat(PrincipalDomain.forDomain("brandx").scoped()).isTrue();
        assertThat(PrincipalDomain.forDomain(null).domain()).isEqualTo(PrincipalDomain.NO_DOMAIN);
        PrincipalDomain sys = PrincipalDomain.superadminFor("brandx");
        assertThat(sys.superadmin()).isTrue();
        assertThat(sys.domain()).isEqualTo("brandx");
    }
}

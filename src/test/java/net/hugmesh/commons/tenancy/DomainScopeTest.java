package net.hugmesh.commons.tenancy;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for the canonical static {@link DomainScope} SQL-predicate utility: a
 * concrete domain appends {@code AND domain = :domain} (scoped tenant); a null/blank
 * domain appends nothing (the SUPERADMIN cross-domain bypass).
 */
class DomainScopeTest {

    @Test
    void concreteDomain_isScoped_andAppendsPredicate() {
        assertThat(DomainScope.isUnscoped("brandx")).isFalse();
        assertThat(DomainScope.andPredicate("brandx")).isEqualTo(" AND domain = :domain");
    }

    @Test
    void nullOrBlankDomain_isUnscoped_appendsNothing() {
        assertThat(DomainScope.isUnscoped(null)).isTrue();
        assertThat(DomainScope.isUnscoped("")).isTrue();
        assertThat(DomainScope.isUnscoped("   ")).isTrue();
        assertThat(DomainScope.andPredicate(null)).isEmpty();
        assertThat(DomainScope.andPredicate("  ")).isEmpty();
    }

    @Test
    void paramName_isStable() {
        assertThat(DomainScope.PARAM).isEqualTo("domain");
    }
}

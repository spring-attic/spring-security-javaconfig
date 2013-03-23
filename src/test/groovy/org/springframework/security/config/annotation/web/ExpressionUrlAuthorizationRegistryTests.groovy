package org.springframework.security.config.annotation.web;

import org.springframework.security.config.annotation.SecurityExpressions.*;

import spock.lang.Specification

public class ExpressionUrlAuthorizationRegistryTests extends Specification {

    def "hasAnyAuthority('ROLE_USER')"() {
        when:
        def expression = ExpressionUrlAuthorizationRegistry.hasAnyAuthority("ROLE_USER")
        then:
        expression == "hasAnyAuthority('ROLE_USER')"
    }

    def "hasAnyAuthority('ROLE_USER','ROLE_ADMIN')"() {
        when:
        def expression = ExpressionUrlAuthorizationRegistry.hasAnyAuthority("ROLE_USER","ROLE_ADMIN")
        then:
        expression == "hasAnyAuthority('ROLE_USER','ROLE_ADMIN')"
    }

    def "hasRole('ROLE_USER') is rejected due to starting with ROLE_"() {
        when:
        def expression = ExpressionUrlAuthorizationRegistry.hasRole("ROLE_USER")
        then:
        IllegalArgumentException e = thrown()
        e.message == "role should not start with 'ROLE_' since it is automatically inserted. Got 'ROLE_USER'"
    }
}

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
}

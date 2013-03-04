package org.springframework.security.config.annotation;

import org.springframework.security.config.annotation.SecurityExpressions.*;

import spock.lang.Specification

public class SecurityExpressionsTests extends Specification {

    def "hasAnyAuthority('ROLE_USER')"() {
        when:
        def expression = SecurityExpressions.hasAnyAuthority("ROLE_USER")
        then:
        expression == "hasAnyAuthority('ROLE_USER')"
    }

    def "hasAnyAuthority('ROLE_USER','ROLE_ADMIN')"() {
        when:
        def expression = SecurityExpressions.hasAnyAuthority("ROLE_USER","ROLE_ADMIN")
        then:
        expression == "hasAnyAuthority('ROLE_USER','ROLE_ADMIN')"
    }
}

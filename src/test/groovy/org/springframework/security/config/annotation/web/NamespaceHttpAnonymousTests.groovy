/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.config.annotation.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/**
 * Tests to verify that all the functionality of <anonymous> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpAnonymousTests extends BaseSpringSpec {
    def "http/anonymous@enabled = true (default)"() {
        when:
        loadConfig(AnonymousConfig)
        then:
        def filter = findFilter(AnonymousAuthenticationFilter)
        filter != null
        def authManager = findFilter(FilterSecurityInterceptor).authenticationManager
        authManager.authenticate(new AnonymousAuthenticationToken(filter.key, filter.principal, filter.authorities)).authenticated
    }

    @Configuration
    static class AnonymousConfig extends BaseWebConfig {
        protected void configure(
                HttpConfiguration springSecurityFilterChain) {
        }
    }

    def "http/anonymous@enabled = false"() {
        when:
        loadConfig(AnonymousDisabledConfig)
        then:
        findFilter(AnonymousAuthenticationFilter) == null
    }

    @Configuration
    static class AnonymousDisabledConfig extends BaseWebConfig {
        protected void configure(
                HttpConfiguration builder) {
                builder.anonymous().disable()
        }
    }

    def "http/anonymous@granted-authority"() {
        when:
        loadConfig(AnonymousGrantedAuthorityConfig)
        then:
        findFilter(AnonymousAuthenticationFilter).authorities == AuthorityUtils.createAuthorityList("ROLE_ANON")
    }

    @Configuration
    static class AnonymousGrantedAuthorityConfig extends BaseWebConfig {
        protected void configure(
            HttpConfiguration builder) {
            builder.anonymous().authorities("ROLE_ANON")
        }
    }


    def "http/anonymous@key"() {
        when:
        loadConfig(AnonymousKeyConfig)
        then:
        def filter = findFilter(AnonymousAuthenticationFilter)
        filter != null
        filter.key == "AnonymousKeyConfig"
        def authManager = findFilter(FilterSecurityInterceptor).authenticationManager
        authManager.authenticate(new AnonymousAuthenticationToken(filter.key, filter.principal, filter.authorities)).authenticated
    }

    @Configuration
    static class AnonymousKeyConfig extends BaseWebConfig {
        protected void configure(
            HttpConfiguration builder) {
            builder.anonymous().key("AnonymousKeyConfig")
        }
    }

    def "http/anonymous@username"() {
        when:
        loadConfig(AnonymousUsernameConfig)
        then:
        def filter = findFilter(AnonymousAuthenticationFilter)
        filter != null
        filter.principal == "AnonymousUsernameConfig"
        def authManager = findFilter(FilterSecurityInterceptor).authenticationManager
        authManager.authenticate(new AnonymousAuthenticationToken(filter.key, filter.principal, filter.authorities)).principal == "AnonymousUsernameConfig"
    }

    @Configuration
    static class AnonymousUsernameConfig extends BaseWebConfig {
        protected void configure(
            HttpConfiguration builder) {
            builder.anonymous().principal("AnonymousUsernameConfig")
        }
    }
}

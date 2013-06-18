/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web;

import org.springframework.context.annotation.Configuration
import org.springframework.security.access.vote.AffirmativeBased
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.SecurityExpressions.*
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor

/**
 *
 * @author Rob Winch
 *
 */
public class UrlAuthorizationsTests extends BaseSpringSpec {

    def "hasAnyAuthority('ROLE_USER')"() {
        when:
            def expression = UrlAuthorizations.hasAnyAuthority("ROLE_USER")
        then:
            expression == ["ROLE_USER"]
    }

    def "hasAnyAuthority('ROLE_USER','ROLE_ADMIN')"() {
        when:
            def expression =  UrlAuthorizations.hasAnyAuthority("ROLE_USER","ROLE_ADMIN")
        then:
            expression == ["ROLE_USER","ROLE_ADMIN"]
    }

    def "hasAnyRole('USER')"() {
        when:
            def expression = UrlAuthorizations.hasAnyRole("USER")
        then:
            expression == ["ROLE_USER"]
    }

    def "hasAnyRole('ROLE_USER','ROLE_ADMIN')"() {
        when:
            def expression =  UrlAuthorizations.hasAnyRole("USER","ADMIN")
        then:
            expression == ["ROLE_USER","ROLE_ADMIN"]
    }

    def "uses AffirmativeBased AccessDecisionManager"() {
        when: "Load Config with no specific AccessDecisionManager"
            loadConfig(NoSpecificAccessDecessionManagerConfig)
        then: "AccessDecessionManager matches the HttpConfigurationBuilder's default"
            findFilter(FilterSecurityInterceptor).accessDecisionManager.class == AffirmativeBased
    }

    @EnableWebSecurity
    @Configuration
    static class NoSpecificAccessDecessionManagerConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .apply(new UrlAuthorizations())
                    .anyRequest().hasRole("USER")
        }
    }
}

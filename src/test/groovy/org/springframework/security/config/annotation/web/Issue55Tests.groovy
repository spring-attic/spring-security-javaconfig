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
package org.springframework.security.config.annotation.web

import static org.springframework.security.config.annotation.web.util.RequestMatchers.*

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.stereotype.Component
import org.springframework.util.Assert;

/**
 *
 * @author Rob Winch
 */
class Issue55Tests extends BaseSpringSpec {

    def "WebSecurityConfigurerAdapter defaults to @Autowired"() {
        when:
        loadConfig(WebSecurityConfigurerAdapterDefaultsAuthManagerConfig)
        then:
        context.getBean(FilterChainProxy)
        findFilter(FilterSecurityInterceptor).authenticationManager.parent.class == CustomAuthenticationManager
     }

    @Configuration
    @EnableWebSecurity
    static class WebSecurityConfigurerAdapterDefaultsAuthManagerConfig {
        @Component
        public static class WebSecurityAdapter extends WebSecurityConfigurerAdapter {
            @Override
            protected void authorizeUrls(ExpressionUrlAuthorizations interceptUrls) {
                interceptUrls.antMatchers("/**").hasRole("USER");
            }

            @Override
            protected void configure(HttpConfiguration http) throws Exception {
            }

            @Override
            protected AuthenticationManager authenticationManager(AuthenticationBuilder builder) throws Exception {
                return null;
            }

        }
        @Configuration
        public static class AuthenticationManagerConfiguration {
            @Bean
            public AuthenticationManager authenticationManager() throws Exception {
                return new CustomAuthenticationManager();
            }
        }
    }

    def "multi http WebSecurityConfigurerAdapter defaults to @Autowired"() {
        when:
        loadConfig(MultiWebSecurityConfigurerAdapterDefaultsAuthManagerConfig)
        then:
        context.getBean(FilterChainProxy)
        findFilter(FilterSecurityInterceptor).authenticationManager.parent.class == CustomAuthenticationManager
        findFilter(FilterSecurityInterceptor,1).authenticationManager.parent.class == CustomAuthenticationManager
     }

    @Configuration
    @EnableWebSecurity
    static class MultiWebSecurityConfigurerAdapterDefaultsAuthManagerConfig {
        @Component
        @Order(1)
        public static class ApiWebSecurityAdapter extends WebSecurityConfigurerAdapter {
            @Override
            protected void authorizeUrls(ExpressionUrlAuthorizations interceptUrls) {
                interceptUrls.antMatchers("/**").hasRole("USER");
            }

            @Override
            protected void configure(HttpConfiguration http) throws Exception {
                http.antMatcher("/api/**");
            }

            @Override
            protected AuthenticationManager authenticationManager(AuthenticationBuilder builder) throws Exception {
                return null;
            }

        }
        @Component
        public static class WebSecurityAdapter extends WebSecurityConfigurerAdapter {
            @Override
            protected void authorizeUrls(ExpressionUrlAuthorizations interceptUrls) {
                interceptUrls.antMatchers("/**").hasRole("USER");
            }

            @Override
            protected void configure(HttpConfiguration http) throws Exception {
            }

            @Override
            protected AuthenticationManager authenticationManager(AuthenticationBuilder builder) throws Exception {
                return null;
            }

        }
        @Configuration
        public static class AuthenticationManagerConfiguration {
            @Bean
            public AuthenticationManager authenticationManager() throws Exception {
                return new CustomAuthenticationManager();
            }
        }
    }

    static class CustomAuthenticationManager implements AuthenticationManager {
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            return null;
        }
    }
}

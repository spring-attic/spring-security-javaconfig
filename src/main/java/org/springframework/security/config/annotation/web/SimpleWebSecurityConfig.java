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


import java.util.Collections;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.util.RequestMatcher;

/**
 * @author Rob Winch
 *
 */
@Configuration
@EnableWebSecurity
public abstract class SimpleWebSecurityConfig {

    protected AuthenticationManager authenticationMgr() throws Exception {
        return null;
    }

    protected DefaultSecurityFilterConfigurator defaultFilterConfigurator() {
        ExpressionUrlAuthorizationBuilder interceptUrls = new ExpressionUrlAuthorizationBuilder();
        authorizeUrls(interceptUrls);
        return new DefaultSecurityFilterConfigurator(interceptUrls)
            .permitAll();
    }

    protected abstract void authorizeUrls(ExpressionUrlAuthorizationBuilder interceptUrls);

    @Bean
    public FilterChainProxySecurityBuilder springSecurityFilterChainBuilder() throws Exception {
        SecurityFilterChainSecurityBuilder springSecurityFilterChain = new SecurityFilterChainSecurityBuilder(authenticationMgr())
            .apply(defaultFilterConfigurator());
        configure(springSecurityFilterChain);

        FilterChainProxySecurityBuilder result = new FilterChainProxySecurityBuilder()
            .securityFilterChains(springSecurityFilterChain);
        configure(result);
        return result;
    }

    protected void configure(FilterChainProxySecurityBuilder securityFilterChains){
        securityFilterChains
            .ignoring(ignoredRequests());
    }

    protected List<RequestMatcher> ignoredRequests() {
        return Collections.emptyList();
    }

    protected abstract void configure(SecurityFilterChainSecurityBuilder springSecurityFilterChain);
}
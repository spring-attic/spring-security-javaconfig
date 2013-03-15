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
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.RequestMatcher;

/**
 * @author Rob Winch
 *
 */
@Configuration
@EnableWebSecurity
public abstract class SimpleWebSecurityConfig {
    private AuthenticationRegistry authenticationRegistry = new AuthenticationRegistry();

    protected abstract void registerAuthentication(AuthenticationRegistry authenticationRegistry) throws Exception;

    protected void applyDefaults(SecurityFilterChainSecurityBuilder builder) throws Exception {
        builder.applyDefaultConfigurators();
        authorizeUrls(builder.authorizeUrls());
    }

    protected abstract void authorizeUrls(ExpressionUrlAuthorizationRegistry interceptUrls);

    @Bean
    public FilterChainProxySecurityBuilder springSecurityFilterChainBuilder() throws Exception {
        SecurityFilterChainSecurityBuilder springSecurityFilterChain = new SecurityFilterChainSecurityBuilder(authenticationManager());
        applyDefaults(springSecurityFilterChain);
        configure(springSecurityFilterChain);

        FilterChainProxySecurityBuilder result = new FilterChainProxySecurityBuilder()
            .securityFilterChains(springSecurityFilterChain);
        result.ignoring(ignoredRequests());
        configure(result);
        return result;
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        registerAuthentication(authenticationRegistry);
        return authenticationRegistry.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return authenticationRegistry.userDetailsService();
    }

    protected void configure(FilterChainProxySecurityBuilder securityFilterChains){
    }

    protected List<RequestMatcher> ignoredRequests() {
        return Collections.emptyList();
    }

    protected abstract void configure(SecurityFilterChainSecurityBuilder springSecurityFilterChain) throws Exception;
}
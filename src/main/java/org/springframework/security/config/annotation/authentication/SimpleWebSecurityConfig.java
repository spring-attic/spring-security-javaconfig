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
package org.springframework.security.config.annotation.authentication;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.DefaultSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.FilterChainProxySecurityBuilder;
import org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;

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
        return new DefaultSecurityFilterConfigurator(filterInvocationBuilder())
            .permitAll();
    }

    protected abstract FilterInvocationSecurityMetadataSourceSecurityBuilder filterInvocationBuilder();

    @Bean
    public FilterChainProxySecurityBuilder springSecurityFilterChainBuilder() throws Exception {
        SecurityFilterChainSecurityBuilder springSecurityFilterChain = new SecurityFilterChainSecurityBuilder(authenticationMgr())
            .apply(defaultFilterConfigurator());

        return configure(new FilterChainProxySecurityBuilder()
            .securityFilterChains(
                configure(springSecurityFilterChain)
            ));
    }

    protected abstract FilterChainProxySecurityBuilder configure(FilterChainProxySecurityBuilder securityFilterChains);

    protected abstract SecurityFilterChainSecurityBuilder configure(SecurityFilterChainSecurityBuilder springSecurityFilterChain);
}
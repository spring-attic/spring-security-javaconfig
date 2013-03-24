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
package org.springframework.security.config.annotation

import java.rmi.registry.Registry;

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder;
import org.springframework.security.config.annotation.authentication.UserDetailsServiceSecurityBuilder;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder
import org.springframework.security.config.annotation.web.UrlAuthorizations
import org.springframework.security.core.userdetails.UserDetailsService;


/**
 *
 * @author Rob Winch
 */
@Configuration
class BaseAuthenticationConfig {
    protected void registerAuthentication(
                AuthenticationBuilder authenticationRegistry) throws Exception {
        authenticationRegistry
            .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER").and()
                .withUser("admin").password("password").roles("USER", "ADMIN").and()
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        AuthenticationBuilder registry = new AuthenticationBuilder();
        registerAuthentication(registry);
        return registry.build();
    }
}

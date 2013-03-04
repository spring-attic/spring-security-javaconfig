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

import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.UserDetailsServiceSecurityBuilder;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder
import org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder
import org.springframework.security.core.userdetails.UserDetailsService;


/**
 *
 * @author Rob Winch
 */
@Configuration
class BaseAuthenticationConfig {
    @Bean
    public AuthenticationManager authenticationMgr() throws Exception {
        return authenticationManager((UserDetailsServiceSecurityBuilder<? extends UserDetailsService>)userDetailsManager()).build();
    }

    @Bean
    public InMemoryUserDetailsManagerSecurityBuilder userDetailsManager() throws Exception {
        return inMemoryAuthentication(
        user("user").password("password").roles("USER"),
        user("admin").password("password").roles("USER", "ADMIN"));
    }
}

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

import static org.springframework.security.config.annotation.SecurityExpressions.hasRole
import static org.springframework.security.config.annotation.SecurityExpressions.permitAll
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*
import static org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder.*

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.BaseAuthenticationConfig;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder

/**
 *
 * @author Rob Winch
 */
@Configuration
@EnableWebSecurity
class BaseWebConfig extends BaseAuthenticationConfig {
    protected fsiSourceBldr() {
        new FilterInvocationSecurityMetadataSourceSecurityBuilder()
                .interceptUrl(antMatchers("/users**","/sessions/**"), hasRole("ADMIN"))
                .interceptUrl(antMatchers("/signup"), permitAll)
                .antInterceptUrl("/**", hasRole("USER"));
    }
}

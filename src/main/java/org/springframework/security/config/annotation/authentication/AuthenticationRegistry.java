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

import javax.sql.DataSource;

import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ldap.LdapAuthenticationProviderBuilderSecurityBuilder;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder;
import org.springframework.security.config.annotation.provisioning.JdbcUserDetailsManagerSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author Rob Winch
 *
 */
public class AuthenticationRegistry implements SecurityBuilder<AuthenticationManager> {
    private SecurityBuilder<AuthenticationManager> builder;

    public InMemoryUserDetailsManagerSecurityBuilder inMemoryAuthentication() {
        InMemoryUserDetailsManagerSecurityBuilder inMemoryBuilder = new InMemoryUserDetailsManagerSecurityBuilder();
        builder = inMemoryBuilder;
        return inMemoryBuilder;
    }

    // FIXME what if ldap not on classpath?
    public LdapAuthenticationProviderBuilderSecurityBuilder ldapAuthenticationProvider(BaseLdapPathContextSource contextSource) {
        LdapAuthenticationProviderBuilderSecurityBuilder ldapBuilder = new LdapAuthenticationProviderBuilderSecurityBuilder(contextSource);
        builder = ldapBuilder;
        return ldapBuilder;
    }

    // FIXME what if DataSource not on classpath?
    public JdbcUserDetailsManagerSecurityBuilder jdbcUserDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManagerSecurityBuilder jdbcBuilder = new JdbcUserDetailsManagerSecurityBuilder(dataSource);
        builder = jdbcBuilder;
        return jdbcBuilder;
    }

    public DaoAuthenticationProviderSecurityBuilder userDetails(UserDetailsService userDetailsService) {
        DaoAuthenticationProviderSecurityBuilder udsBuilder = new DaoAuthenticationProviderSecurityBuilder(userDetailsService);
        builder = udsBuilder;
        return udsBuilder;
    }

    public AuthenticationManager build() throws Exception {
        if(builder == null) {
            throw new IllegalStateException("builder must be initialized");
        }
        return builder.build();
    }
}
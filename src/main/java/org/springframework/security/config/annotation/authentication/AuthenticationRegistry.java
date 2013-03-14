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
import org.springframework.security.authentication.AuthenticationProvider;
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
    private final AuthenticationManagerSecurityBuilder builder = new AuthenticationManagerSecurityBuilder();
    private UserDetailsService userDetailsService;

    public InMemoryUserDetailsManagerSecurityBuilder inMemoryAuthentication() {
        InMemoryUserDetailsManagerSecurityBuilder inMemoryBuilder = new InMemoryUserDetailsManagerSecurityBuilder();
        userDetails(inMemoryBuilder.userDetailsService());
        return inMemoryBuilder;
    }

    // FIXME what if ldap not on classpath?
    public LdapAuthenticationProviderBuilderSecurityBuilder ldapAuthenticationProvider(BaseLdapPathContextSource contextSource) throws Exception {
        LdapAuthenticationProviderBuilderSecurityBuilder ldapBuilder = new LdapAuthenticationProviderBuilderSecurityBuilder(contextSource);
        authenticationProvider(ldapBuilder.ldapAuthenticationProvider());
        return ldapBuilder;
    }

    // FIXME what if DataSource not on classpath?
    public JdbcUserDetailsManagerSecurityBuilder jdbcUserDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManagerSecurityBuilder jdbcBuilder = new JdbcUserDetailsManagerSecurityBuilder(dataSource);
        userDetails(jdbcBuilder.userDetailsService());
        return jdbcBuilder;
    }

    public DaoAuthenticationProviderSecurityBuilder userDetails(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
        builder.userDetails(userDetailsService);
        DaoAuthenticationProviderSecurityBuilder udsBuilder = new DaoAuthenticationProviderSecurityBuilder(userDetailsService);
        return udsBuilder;
    }

    public DaoAuthenticationProviderSecurityBuilder authenticationProvider(AuthenticationProvider authenticationProvider) {
        builder.authenticationProvider(authenticationProvider);
        DaoAuthenticationProviderSecurityBuilder udsBuilder = new DaoAuthenticationProviderSecurityBuilder(userDetailsService);
        return udsBuilder;
    }

    public UserDetailsService userDetailsService() {
        return userDetailsService;
    }

    public AuthenticationManager build() throws Exception {
        if(builder == null) {
            throw new IllegalStateException("builder must be initialized");
        }
        return builder.build();
    }
}
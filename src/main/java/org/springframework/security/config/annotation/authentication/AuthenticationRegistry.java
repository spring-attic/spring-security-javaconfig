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

import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.AbstractConfiguredBuilder;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ldap.LdapAuthenticationProviderBuilderSecurityBuilder;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder;
import org.springframework.security.config.annotation.provisioning.JdbcUserDetailsManagerSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author Rob Winch
 *
 */
public class AuthenticationRegistry extends AbstractConfiguredBuilder<AuthenticationManager, AuthenticationRegistry>implements
        SecurityBuilder<AuthenticationManager> {
    private AuthenticationManager parentAuthenticationManager;
    private List<AuthenticationProvider> authenticationProviders = new ArrayList<AuthenticationProvider>();
    private UserDetailsService userDetailsService;

    public AuthenticationRegistry parentAuthenticationManager(
            AuthenticationManager authenticationManager) {
        this.parentAuthenticationManager = authenticationManager;
        return this;
    }

    public InMemoryUserDetailsManagerSecurityBuilder inMemoryAuthentication()
            throws Exception {
        return apply(new InMemoryUserDetailsManagerSecurityBuilder());
    }

    // FIXME what if ldap not on classpath?
    public LdapAuthenticationProviderBuilderSecurityBuilder ldapAuthenticationProvider(
            BaseLdapPathContextSource contextSource) throws Exception {
        return apply(new LdapAuthenticationProviderBuilderSecurityBuilder(
                contextSource));
    }

    // FIXME what if DataSource not on classpath?
    public JdbcUserDetailsManagerSecurityBuilder jdbcUserDetailsManager(
            DataSource dataSource) throws Exception {
        return apply(new JdbcUserDetailsManagerSecurityBuilder(dataSource));
    }

    public DaoAuthenticationConfigurator userDetails(
            UserDetailsService userDetailsService) throws Exception {
        this.userDetailsService = userDetailsService;
        return apply(new DaoAuthenticationConfigurator(userDetailsService));
    }

    public AuthenticationRegistry add(
            AuthenticationProvider authenticationProvider) {
        this.authenticationProviders.add(authenticationProvider);
        return this;
    }

    public AuthenticationRegistry add(
            UserDetailsService userDetailsService) throws Exception {
        DaoAuthenticationConfigurator provider = new DaoAuthenticationConfigurator(userDetailsService);
        provider.init(this);
        provider.configure(this);
        return this;
    }

    public AuthenticationManager build() throws Exception {
        init();
        configure();
        return new ProviderManager(authenticationProviders,
                parentAuthenticationManager);
    }

    /**
     * @return
     */
    public UserDetailsService userDetailsService() {
        return this.userDetailsService;
    }
}
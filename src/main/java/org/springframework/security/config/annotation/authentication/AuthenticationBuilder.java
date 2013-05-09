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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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
public class AuthenticationBuilder extends AbstractConfiguredBuilder<AuthenticationManager, AuthenticationBuilder> implements
        SecurityBuilder<AuthenticationManager>, AuthenticationRegistry {
    private AuthenticationManager parentAuthenticationManager;
    private List<AuthenticationProvider> authenticationProviders = new ArrayList<AuthenticationProvider>();
    private UserDetailsService userDetailsService;

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#parentAuthenticationManager(org.springframework.security.authentication.AuthenticationManager)
     */
    public AuthenticationBuilder parentAuthenticationManager(
            AuthenticationManager authenticationManager) {
        this.parentAuthenticationManager = authenticationManager;
        return this;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#inMemoryAuthentication()
     */
    public InMemoryUserDetailsManagerSecurityBuilder inMemoryAuthentication()
            throws Exception {
        return apply(new InMemoryUserDetailsManagerSecurityBuilder());
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#ldapAuthenticationProvider(org.springframework.ldap.core.support.BaseLdapPathContextSource)
     */
    public LdapAuthenticationProviderBuilderSecurityBuilder ldapAuthenticationProvider() throws Exception {
        return apply(new LdapAuthenticationProviderBuilderSecurityBuilder());
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#jdbcUserDetailsManager(javax.sql.DataSource)
     */
    public JdbcUserDetailsManagerSecurityBuilder jdbcUserDetailsManager() throws Exception {
        return apply(new JdbcUserDetailsManagerSecurityBuilder());
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#userDetails(org.springframework.security.core.userdetails.UserDetailsService)
     */
    public DaoAuthenticationConfigurator userDetails(
            UserDetailsService userDetailsService) throws Exception {
        this.userDetailsService = userDetailsService;
        return apply(new DaoAuthenticationConfigurator(userDetailsService));
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#add(org.springframework.security.authentication.AuthenticationProvider)
     */
    public AuthenticationRegistry add(
            AuthenticationProvider authenticationProvider) {
        this.authenticationProviders.add(authenticationProvider);
        return this;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#add(org.springframework.security.core.userdetails.UserDetailsService)
     */
    public AuthenticationRegistry add(
            UserDetailsService userDetailsService) throws Exception {
        this.userDetailsService = userDetailsService;
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        return add(provider);
    }

    protected AuthenticationManager performBuild() throws Exception {
        return new ProviderManager(authenticationProviders,
                parentAuthenticationManager);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#userDetailsService()
     */
    public UserDetailsService userDetailsService() {
        return this.userDetailsService;
    }
}
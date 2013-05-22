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
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ldap.LdapAuthenticationProviderConfigurator;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder;
import org.springframework.security.config.annotation.provisioning.JdbcUserDetailsManagerConfigurator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * {@link SecurityBuilder} used to create an {@link AuthenticationManager}.
 * Allows for easily building in memory authentication, LDAP authentication,
 * JDBC based authentication, adding {@link UserDetailsService}, and adding
 * {@link AuthenticationProvider}'s.
 *
 * @author Rob Winch
 * @since 3.2
 */
public class AuthenticationManagerBuilder extends AbstractConfiguredSecurityBuilder<AuthenticationManager, AuthenticationManagerBuilder>
        implements SecurityBuilder<AuthenticationManager>, AuthenticationRegistry {

    private AuthenticationManager parentAuthenticationManager;
    private List<AuthenticationProvider> authenticationProviders = new ArrayList<AuthenticationProvider>();
    private UserDetailsService defaultUserDetailsService;

    /**
     * Allows providing a parent {@link AuthenticationManager} that will be
     * tried if this {@link AuthenticationManager} was unable to attempt to
     * authenticate the provided {@link Authentication}.
     *
     * @param authenticationManager
     *            the {@link AuthenticationManager} that should be used if the
     *            current {@link AuthenticationManager} was unable to attempt to
     *            authenticate the provided {@link Authentication}.
     * @return the {@link AuthenticationManagerBuilder} for further adding types
     *         of authentication
     */
    public AuthenticationManagerBuilder parentAuthenticationManager(
            AuthenticationManager authenticationManager) {
        this.parentAuthenticationManager = authenticationManager;
        return this;
    }

    /**
     * <p>
     * This method also ensure that a {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * </p>
     *
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#inMemoryAuthentication()
     */
    @Override
    public InMemoryUserDetailsManagerSecurityBuilder inMemoryAuthentication()
            throws Exception {
        return apply(new InMemoryUserDetailsManagerSecurityBuilder());
    }

    /**
     * <p>
     * This method <b>does NOT</b> ensure that a {@link UserDetailsService} is
     * available for the {@link #getDefaultUserDetailsService()} method.
     * </p>
     *
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#ldapAuthenticationProvider()
     */
    @Override
    public LdapAuthenticationProviderConfigurator ldapAuthenticationProvider()
            throws Exception {
        return apply(new LdapAuthenticationProviderConfigurator());
    }

    /**
     * <p>
     * This method also ensure that a {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * </p>
     *
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#jdbcUserDetailsManager()
     */
    @Override
    public JdbcUserDetailsManagerConfigurator jdbcUserDetailsManager()
            throws Exception {
        return apply(new JdbcUserDetailsManagerConfigurator());
    }

    /**
     * <p>
     * This method also ensure that a {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * </p>
     *
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#userDetailsService(org.springframework.security.core.userdetails.UserDetailsService)
     */
    @Override
    public DaoAuthenticationConfigurator userDetailsService(
            UserDetailsService userDetailsService) throws Exception {
        this.defaultUserDetailsService = userDetailsService;
        return apply(new DaoAuthenticationConfigurator(userDetailsService));
    }

    /**
     * <p>
     * This method <b>does NOT</b> ensure that a {@link UserDetailsService} is
     * available for the {@link #getDefaultUserDetailsService()} method.
     * </p>
     *
     * @see org.springframework.security.config.annotation.authentication.AuthenticationRegistry#add(org.springframework.security.authentication.AuthenticationProvider)
     */
    @Override
    public AuthenticationRegistry add(
            AuthenticationProvider authenticationProvider) {
        this.authenticationProviders.add(authenticationProvider);
        return this;
    }

    @Override
    protected AuthenticationManager performBuild() throws Exception {
        return new ProviderManager(authenticationProviders,
                parentAuthenticationManager);
    }

    /**
     * Gets the default {@link UserDetailsService} for the
     * {@link AuthenticationManagerBuilder}. The result may be null in some
     * circumstances.
     *
     * @return
     */
    public UserDetailsService getDefaultUserDetailsService() {
        return this.defaultUserDetailsService;
    }

    private <C extends UserDetailsServiceConfigurator<?>> C apply(C configurer)
            throws Exception {
        this.defaultUserDetailsService = configurer.getUserDetailsService();
        return (C) super.apply(configurer);
    }
}
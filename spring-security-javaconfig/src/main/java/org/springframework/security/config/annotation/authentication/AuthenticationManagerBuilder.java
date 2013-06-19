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
import org.springframework.security.config.annotation.LifecycleManager;
import org.springframework.security.config.annotation.SecurityBuilder;
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
public class AuthenticationManagerBuilder extends AbstractConfiguredSecurityBuilder<AuthenticationManager, AuthenticationManagerBuilder> implements ProviderManagerBuilder<AuthenticationManagerBuilder> {

    private LifecycleManager lifecycleManager;

    private AuthenticationManager parentAuthenticationManager;
    private List<AuthenticationProvider> authenticationProviders = new ArrayList<AuthenticationProvider>();
    private UserDetailsService defaultUserDetailsService;

    /**
     * Sets the {@link LifecycleManager} to be used on the {@link AuthenticationManagerBuilder}
     * @param lifecycleManager
     * @return the {@link AuthenticationManagerBuilder} for further customizations
     */
    public AuthenticationManagerBuilder lifecycleManager(LifecycleManager lifecycleManager) {
        this.lifecycleManager = lifecycleManager;
        return this;
    }

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
     * Add in memory authentication to the {@link AuthenticationManagerBuilder}
     * and return a {@link InMemoryUserDetailsManagerConfigurer} to
     * allow customization of the in memory authentication.
     *
     * <p>
     * This method also ensure that a {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * </p>
     *
     * @return a {@link InMemoryUserDetailsManagerConfigurer} to allow
     *         customization of the in memory authentication
     * @throws Exception
     *             if an error occurs when adding the in memory authentication
     */
    public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
            throws Exception {
        return apply(new InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder>());
    }

    /**
     * Add JDBC authentication to the {@link AuthenticationManagerBuilder} and
     * return a {@link JdbcUserDetailsManagerConfigurer} to allow customization of the
     * JDBC authentication.
     *
     * <p>
     * This method also ensure that a {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * </p>
     *
     * @return a {@link JdbcUserDetailsManagerConfigurer} to allow customization of the
     * JDBC authentication
     * @throws Exception if an error occurs when adding the JDBC authentication
     */
    public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcUserDetailsManager()
            throws Exception {
        return apply(new JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder>());
    }

    /**
     * Add authentication based upon the custom {@link UserDetailsService} that
     * is passed in. It then returns a {@link DaoAuthenticationConfigurer} to
     * allow customization of the authentication.
     *
     * <p>
     * This method also ensure that the {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * </p>
     *
     * @return a {@link DaoAuthenticationConfigurer} to allow customization
     *         of the DAO authentication
     * @throws Exception
     *             if an error occurs when adding the {@link UserDetailsService}
     *             based authentication
     */
    public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder,T> userDetailsService(
            T userDetailsService) throws Exception {
        this.defaultUserDetailsService = userDetailsService;
        return apply(new DaoAuthenticationConfigurer<AuthenticationManagerBuilder,T>(userDetailsService));
    }

    /**
     * Add authentication based upon the custom {@link AuthenticationProvider}
     * that is passed in. Since the {@link AuthenticationProvider}
     * implementation is unknown, all customizations must be done externally and
     * the {@link AuthenticationManagerBuilder} is returned immediately.
     *
     * <p>
     * This method <b>does NOT</b> ensure that the {@link UserDetailsService} is
     * available for the {@link #getDefaultUserDetailsService()} method.
     * </p>
     *
     * @return a {@link AuthenticationManagerBuilder} to allow further authentication
     *         to be provided to the {@link AuthenticationManagerBuilder}
     * @throws Exception
     *             if an error occurs when adding the {@link AuthenticationProvider}
     */
    public AuthenticationManagerBuilder add(
            AuthenticationProvider authenticationProvider) {
        authenticationProvider = registerLifecycle(authenticationProvider);
        this.authenticationProviders.add(authenticationProvider);
        return this;
    }

    @Override
    protected AuthenticationManager performBuild() throws Exception {
        return new ProviderManager(authenticationProviders,
                parentAuthenticationManager);
    }

    private <T> T registerLifecycle(T object) {
        return lifecycleManager == null ? object : lifecycleManager.registerLifecycle(object);
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

    private <C extends UserDetailsAwareConfigurer<AuthenticationManagerBuilder,? extends UserDetailsService>> C apply(C configurer) throws Exception {
        this.defaultUserDetailsService = configurer.getUserDetailsService();
        return (C) super.apply(configurer);
    }
}
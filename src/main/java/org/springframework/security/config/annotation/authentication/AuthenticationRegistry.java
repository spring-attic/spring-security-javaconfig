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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ldap.LdapAuthenticationRegistry;
import org.springframework.security.config.annotation.provisioning.JdbcUserDetailsManagerRegistry;
import org.springframework.security.config.annotation.provisioning.UserDetailsManagerRegistry;
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
public interface AuthenticationRegistry {

    /**
     * Add in memory authentication to the {@link AuthenticationRegistry} and
     * return a {@link UserDetailsManagerRegistry} to allow customization of the
     * in memory authentication.
     *
     * @return a {@link UserDetailsManagerRegistry} to allow customization of
     *         the in memory authentication
     * @throws Exception if an error occurs when adding the in memory authentication
     */
    UserDetailsManagerRegistry<? extends UserDetailsManagerRegistry<?>> inMemoryAuthentication()
            throws Exception;

    /**
     * Add LDAP authentication to the {@link AuthenticationRegistry} and
     * return a {@link LdapAuthenticationRegistry} to allow customization of the
     * LDAP authentication.
     *
     * @return a {@link LdapAuthenticationRegistry} to allow customization of the
     * LDAP authentication
     * @throws Exception if an error occurs when adding the LDAP authentication
     */
    LdapAuthenticationRegistry ldapAuthenticationProvider() throws Exception;

    /**
     * Add JDBC authentication to the {@link AuthenticationRegistry} and
     * return a {@link JdbcUserDetailsManagerRegistry} to allow customization of the
     * JDBC authentication.
     *
     * <p>
     * This method also ensure that a {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * </p>
     *
     * @return a {@link JdbcUserDetailsManagerRegistry} to allow customization of the
     * LDAP authentication
     * @throws Exception if an error occurs when adding the JDBC authentication
     */
    JdbcUserDetailsManagerRegistry<? extends JdbcUserDetailsManagerRegistry<?>> jdbcUserDetailsManager() throws Exception;

    /**
     * Add authentication based upon the custom {@link UserDetailsService} that
     * is passed in. It then returns a {@link DaoAuthenticationConfigurator} to
     * allow customization of the authentication.
     *
     * <p>
     * This method also ensure that the {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * </p>
     *
     * @return a {@link JdbcUserDetailsManagerRegistry} to allow customization
     *         of the LDAP authentication
     * @throws Exception
     *             if an error occurs when adding the {@link UserDetailsService}
     *             based authentication
     */
    <T extends UserDetailsService> DaoAuthenticationConfigurator<? extends DaoAuthenticationConfigurator<?, T>,T> userDetailsService(
            T userDetailsService) throws Exception;

    /**
     * Add authentication based upon the custom {@link AuthenticationProvider}
     * that is passed in. Since the {@link AuthenticationProvider}
     * implementation is unknown, all customizations must be done externally and
     * the {@link AuthenticationRegistry} is returned immediately.
     *
     * <p>
     * This method <b>does NOT</b> ensure that the {@link UserDetailsService} is
     * available for the {@link #getDefaultUserDetailsService()} method.
     * </p>
     *
     * @return a {@link AuthenticationRegistry} to allow further authentication
     *         to be provided to the {@link AuthenticationRegistry}
     * @throws Exception
     *             if an error occurs when adding the {@link AuthenticationProvider}
     */
    AuthenticationRegistry add(
            AuthenticationProvider authenticationProvider);
}
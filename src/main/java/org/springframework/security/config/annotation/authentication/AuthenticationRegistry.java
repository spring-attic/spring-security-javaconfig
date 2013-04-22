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
import org.springframework.security.config.annotation.authentication.ldap.LdapAuthenticationRegistry;
import org.springframework.security.config.annotation.provisioning.JdbcUserDetailsManagerRegistry;
import org.springframework.security.config.annotation.provisioning.UserDetailsManagerRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author Rob Winch
 *
 */
public interface AuthenticationRegistry {

    AuthenticationRegistry parentAuthenticationManager(
            AuthenticationManager authenticationManager);

    UserDetailsManagerRegistry<? extends UserDetailsManagerRegistry<?>> inMemoryAuthentication()
            throws Exception;

    LdapAuthenticationRegistry ldapAuthenticationProvider() throws Exception;

    JdbcUserDetailsManagerRegistry<? extends JdbcUserDetailsManagerRegistry<?>> jdbcUserDetailsManager() throws Exception;

    DaoAuthenticationConfigurator userDetails(
            UserDetailsService userDetailsService) throws Exception;

    AuthenticationRegistry add(
            AuthenticationProvider authenticationProvider);

    AuthenticationRegistry add(
            UserDetailsService userDetailsService) throws Exception;

    UserDetailsService userDetailsService();

}
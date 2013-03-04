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
package org.springframework.security.config.annotation.authentication;

import javax.sql.DataSource;

import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ldap.LdapAuthenticationProviderBuilderSecurityBuilder;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder;
import org.springframework.security.config.annotation.provisioning.JdbcUserDetailsManagerSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class AuthenticationSecurityBuilders {

    public static DaoAuthenticationProviderSecurityBuilder authenticationProvider(UserDetailsServiceSecurityBuilder<? extends UserDetailsService> userDetailsServiceBuilder) throws Exception {
        return new DaoAuthenticationProviderSecurityBuilder(userDetailsServiceBuilder.build());
    }

    public static DaoAuthenticationProviderSecurityBuilder authenticationProvider(UserDetailsService userDetailsService) throws Exception {
        return authenticationProvider(new UserDetailsServiceSecurityBuilder<UserDetailsService>(userDetailsService));
    }

    public static <T> AuthenticationManagerSecurityBuilder authenticationManager(SecurityBuilder<? extends AuthenticationProvider> authenticationProviderBuilder) throws Exception {
        return new AuthenticationManagerSecurityBuilder().authenticationProvider(authenticationProviderBuilder);
    }

    public static <T> AuthenticationManagerSecurityBuilder authenticationManager(UserDetailsServiceSecurityBuilder<? extends UserDetailsService> userDetailsServiceBuilder) throws Exception {
        return new AuthenticationManagerSecurityBuilder().userDetails(userDetailsServiceBuilder);
    }

    public static InMemoryUserDetailsManagerSecurityBuilder inMemoryAuthentication(UserSecurityBuilder... userBuilders) throws Exception {
        return new InMemoryUserDetailsManagerSecurityBuilder().withUsers(userBuilders);
    }

    public static JdbcUserDetailsManagerSecurityBuilder jdbcUserDetailsManager(DataSource dataSource) throws Exception {
        return new JdbcUserDetailsManagerSecurityBuilder(dataSource);
    }

    public static LdapAuthenticationProviderBuilderSecurityBuilder ldapAuthenticationProvider(BaseLdapPathContextSource contextSource) throws Exception {
        return new LdapAuthenticationProviderBuilderSecurityBuilder(contextSource);
    }

    public static UserSecurityBuilder user(String username) {
        return UserSecurityBuilder.user(username);
    }

}
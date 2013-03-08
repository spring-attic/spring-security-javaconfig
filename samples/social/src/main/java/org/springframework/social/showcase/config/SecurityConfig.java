/*
 * Copyright 2011 the original author or authors.
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
package org.springframework.social.showcase.config;

import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*;
import static org.springframework.security.config.annotation.web.WebSecurityConfigurators.*;
import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.provisioning.JdbcUserDetailsManagerSecurityBuilder;
import org.springframework.security.config.annotation.web.DefaultSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizationBuilder;
import org.springframework.security.config.annotation.web.FilterChainProxySecurityBuilder;
import org.springframework.security.config.annotation.web.UrlAuthorizationBuilder;
import org.springframework.security.config.annotation.web.FormLoginSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.LogoutFilterSecurityBuilder;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.social.security.SocialAuthenticationFilter;
import org.springframework.social.security.SocialAuthenticationProvider;

/**
 * Security Configuration.
 * @author Craig Walls
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private DataSource dataSource;

    @Autowired
    private SocialAuthenticationFilter socialAuthenticationFilter;

    @Autowired
    private SocialAuthenticationProvider socialAuthenticationProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public TextEncryptor textEncryptor() {
        return Encryptors.noOpText();
    }

    @Bean
    public AuthenticationManager authenticationMgr() throws Exception {
        return authenticationManager(
            authenticationProvider(userDetailsManager()).passwordEncoder(passwordEncoder())
        )
        .authenticationProvider(socialAuthenticationProvider).build();
    }

    @Bean
    public JdbcUserDetailsManagerSecurityBuilder userDetailsManager() throws Exception {
        return jdbcUserDetailsManager(dataSource)
                .usersByUsernameQuery("select username, password, true from Account where username = ?")
                .authoritiesByUsernameQuery("select username, 'ROLE_USER' from Account where username = ?");
    }

    @Bean
    public FilterChainProxySecurityBuilder builder() throws Exception {
        ExpressionUrlAuthorizationBuilder fiSourceBldr = interceptUrls()
            .antMatchers("/favicon.ico","/resources/**","/auth/**","/signup/**","/disconnect/facebook").permitAll()
            .antMatchers("/**").authenticated();

        return new FilterChainProxySecurityBuilder()
            .ignoring(antMatchers("/resources/**"))
            .securityFilterChains(
                new SecurityFilterChainSecurityBuilder(authenticationMgr())
                    .apply(new DefaultSecurityFilterConfigurator(fiSourceBldr)
                        .withLogout(new LogoutFilterSecurityBuilder()
                                .deleteCookies("JSESSIONID")
                                .logoutUrl("/signout"))
                        .permitAll())
                    .apply(new FormLoginSecurityFilterConfigurator()
                        .loginPage("/signin")
                        .loginProcessingUrl("/signin/authenticate")
                        .failureUrl("/signin?param.error=bad_credentials")
                        .permitAll()
                    )
                    .addFilterBefore(socialAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
            );
    }
}

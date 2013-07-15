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

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private UserDetailsServiceDelegator userDetailsService = new UserDetailsServiceDelegator();

    @Autowired
    private ConfigurableApplicationContext context;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private SocialAuthenticationProvider socialAuthenticationProvider;

    @Autowired
    private SocialAuthenticationFilter socialAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public TextEncryptor textEncryptor() {
        return Encryptors.noOpText();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
            .ignoring()
                .antMatchers("/resources/**");
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean()
            throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    @Override
    public UserDetailsService userDetailsServiceBean() throws Exception {
        return userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeUrls()
                .antMatchers("/favicon.ico","/resources/**","/auth/**","/signup/**","/disconnect/facebook","/signout").permitAll()
                .anyRequest().authenticated()
                .and()
            .addFilterBefore(socialAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
            .logout()
                .deleteCookies("JSESSIONID")
                .logoutUrl("/signout")
                .logoutSuccessUrl("/")
                .and()
            .formLogin()
                .loginPage("/signin")
                .loginProcessingUrl("/signin/authenticate")
                .failureUrl("/signin?param.error=bad_credentials")
                .usernameParameter("j_username")
                .passwordParameter("j_password")
                .permitAll();
    }

    @Override
    protected void registerAuthentication(
            AuthenticationManagerBuilder auth) throws Exception {
        userDetailsService.setBuilder(auth);
        auth
            .jdbcAuthentication()
                .dataSource(dataSource)
                .usersByUsernameQuery("select username, password, true from Account where username = ?")
                .authoritiesByUsernameQuery("select username, 'ROLE_USER' from Account where username = ?")
                .and()
            .authenticationProvider(socialAuthenticationProvider);
    }
    
    /**
     * Workaround for https://jira.springsource.org/browse/SEC-2205
     *
     * @author Rob Winch
     */
    static final class UserDetailsServiceDelegator implements UserDetailsService {
        private AuthenticationManagerBuilder delegateBuilder;
        private UserDetailsService delegate;
        private final Object delegateMonitor = new Object();

        private void setBuilder(AuthenticationManagerBuilder authentication) {
            this.delegateBuilder = authentication;
        }

        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { 
            if(delegate != null) {
                return delegate.loadUserByUsername(username);
            }

            synchronized(delegateMonitor) {
                if (delegate == null) {
                    delegate = this.delegateBuilder.getDefaultUserDetailsService();
                    this.delegateBuilder = null;
                }
            }

            return delegate.loadUserByUsername(username);
        }
    }
}

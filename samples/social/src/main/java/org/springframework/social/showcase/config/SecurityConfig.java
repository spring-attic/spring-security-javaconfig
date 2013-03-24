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

import javax.servlet.Filter;
import javax.sql.DataSource;

import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizations;
import org.springframework.security.config.annotation.web.HttpConfiguration;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapater;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * Security Configuration.
 * @author Craig Walls
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapater {
    @Autowired
    private ConfigurableApplicationContext context;

    @Autowired
    private DataSource dataSource;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public TextEncryptor textEncryptor() {
        return Encryptors.noOpText();
    }

    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
        ignoredRequests
            .antMatchers("/resources/**");
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizations interceptUrls) {
        interceptUrls
            .antMatchers("/favicon.ico","/resources/**","/auth/**","/signup/**","/disconnect/facebook").permitAll()
            .antMatchers("/**").authenticated();
    }

    protected void configure(HttpConfiguration http) throws Exception {
        http
            .addFilterBefore(lazySocialAuthenticationFilter(), AbstractPreAuthenticatedProcessingFilter.class)
            .logout()
                .deleteCookies("JSESSIONID")
                .logoutUrl("/signout")
                .permitAll()
                .and()
            .formLogin()
                .loginPage("/signin")
                .loginProcessingUrl("/signin/authenticate")
                .failureUrl("/signin?param.error=bad_credentials")
                .permitAll();
    }

    protected AuthenticationManager authenticationManager(
            AuthenticationBuilder registry) throws Exception {
        return registry
            .jdbcUserDetailsManager(dataSource)
                .usersByUsernameQuery("select username, password, true from Account where username = ?")
                .authoritiesByUsernameQuery("select username, 'ROLE_USER' from Account where username = ?")
                .and()
           .add(lazySocialAuthenticationProvider())
           .build();
    }

    @Bean
    public Filter lazySocialAuthenticationFilter() {
        return lazyBean("socialAuthenticationFilter",Filter.class);
    }

    @Bean
    public AuthenticationProvider lazySocialAuthenticationProvider() {
        return lazyBean("socialAuthenticationProvider", AuthenticationProvider.class);
    }

    private <T> T lazyBean(String targetBeanName, Class<T> interfaceName) {
        LazyInitTargetSource lazyTargetSource = new LazyInitTargetSource();
        lazyTargetSource.setTargetBeanName(targetBeanName);
        lazyTargetSource.setBeanFactory(context);
        ProxyFactoryBean proxyFactory = new ProxyFactoryBean();
        proxyFactory.setTargetSource(lazyTargetSource);
        proxyFactory.setInterfaces(new Class[] { interfaceName });
        return (T) proxyFactory.getObject();
    }
}

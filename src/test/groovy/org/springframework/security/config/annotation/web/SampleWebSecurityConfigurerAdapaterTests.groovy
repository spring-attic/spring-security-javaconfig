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
package org.springframework.security.config.annotation.web;


import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.BaseAuthenticationConfig;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.BaseWebSpecuritySpec;
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.AntPathRequestMatcher
import org.springframework.security.web.util.AnyRequestMatcher;
import org.springframework.security.web.util.RequestMatcher

/**
 * Demonstrate the samples
 *
 * @author Rob Winch
 *
 */
public class SampleWebSecurityConfigurerAdapaterTests extends BaseWebSpecuritySpec {
    def "README Sample works"() {
        setup:
        loadConfig(SampleWebSecurityConfigurerAdapater)
        when:
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.getRedirectedUrl() == "http://localhost/login"
        when: "fail to log in"
        super.setup()
        request.requestURI = "/login"
        request.method = "POST"
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
        response.getRedirectedUrl() == "/login?error"
        when: "login success"
        super.setup()
        request.requestURI = "/login"
        request.method = "POST"
        request.parameters.username = ["user"] as String[]
        request.parameters.password = ["password"] as String[]
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default succes page"
        response.getRedirectedUrl() == "/"
    }

    /**
     * <code>
     *   <http security="none" pattern="/resources/**"/>
     *   <http use-expressions="true">
     *     <intercept-url pattern="/logout" access="permitAll"/>
     *     <intercept-url pattern="/login" access="permitAll"/>
     *     <intercept-url pattern="/signup" access="permitAll"/>
     *     <intercept-url pattern="/about" access="permitAll"/>
     *     <intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
     *     <logout
     *         logout-success-url="/login?logout"
     *         logout-url="/logout"
     *     <form-login
     *         authentication-failure-url="/login?error"
     *         login-page="/login"
     *         login-processing-url="/login" <!-- but only POST -->
     *         password-parameter="password"
     *         username-parameter="username"
     *     />
     *   </http>
     *   <authentication-manager>
     *     <authentication-provider>
     *       <user-service>
     *         <user username="user" password="password" authorities="ROLE_USER"/>
     *         <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
     *       </user-service>
     *     </authentication-provider>
     *   </authentication-manager>
     * </code>
     * @author Rob Winch
     */
    @Configuration
    @EnableWebSecurity
    public static class SampleWebSecurityConfigurerAdapater extends WebSecurityConfigurerAdapater {
        protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
            ignoredRequests
                .antMatchers("/resources/**");
        }
        protected void authorizeUrls(ExpressionUrlAuthorizations interceptUrls) {
            interceptUrls
                .antMatchers("/signup","/about").permitAll()
                .antMatchers("/**").hasRole("USER");
        }

        protected void configure(HttpConfiguration http) throws Exception {
            http
                .formLogin()
                    .permitAll();
        }

        protected AuthenticationManager authenticationManager(AuthenticationBuilder builder) {
            return builder
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN").and()
                    .and()
                .build();
        }
    }

    def "README Multi http Sample works"() {
        setup:
        loadConfig(SampleMultiHttpSecurityConfig)
        when:
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.getRedirectedUrl() == "http://localhost/login"
        when: "fail to log in"
        super.setup()
        request.requestURI = "/login"
        request.method = "POST"
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
        response.getRedirectedUrl() == "/login?error"
        when: "login success"
        super.setup()
        request.requestURI = "/login"
        request.method = "POST"
        request.parameters.username = ["user"] as String[]
        request.parameters.password = ["password"] as String[]
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default succes page"
        response.getRedirectedUrl() == "/"

        when: "request protected API URL"
        super.setup()
        request.servletPath = "/api/admin/test"
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "get 403"
        response.getStatus() == 403

        when: "request API for admins with user"
        super.setup()
        request.servletPath = "/api/admin/test"
        request.addHeader("Authorization", "Basic " + "user:password".bytes.encodeBase64().toString())
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "get 403"
        response.getStatus() == 403

        when: "request API for admins with admin"
        super.setup()
        request.servletPath = "/api/admin/test"
        request.addHeader("Authorization", "Basic " + "admin:password".bytes.encodeBase64().toString())
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "get 200"
        response.getStatus() == 200
    }


    /**
     * <code>
     *   <http security="none" pattern="/resources/**"/>
     *   <http use-expressions="true" pattern="/api/**">
     *     <intercept-url pattern="/api/admin/**" access="hasRole('ROLE_ADMIN')"/>
     *     <intercept-url pattern="/api/**" access="hasRole('ROLE_USER')"/>
     *     <http-basic />
     *   </http>
     *   <http use-expressions="true">
     *     <intercept-url pattern="/logout" access="permitAll"/>
     *     <intercept-url pattern="/login" access="permitAll"/>
     *     <intercept-url pattern="/signup" access="permitAll"/>
     *     <intercept-url pattern="/about" access="permitAll"/>
     *     <intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
     *     <logout
     *         logout-success-url="/login?logout"
     *         logout-url="/logout"
     *     <form-login
     *         authentication-failure-url="/login?error"
     *         login-page="/login"
     *         login-processing-url="/login" <!-- but only POST -->
     *         password-parameter="password"
     *         username-parameter="username"
     *     />
     *   </http>
     *   <authentication-manager>
     *     <authentication-provider>
     *       <user-service>
     *         <user username="user" password="password" authorities="ROLE_USER"/>
     *         <user username="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
     *       </user-service>
     *     </authentication-provider>
     *   </authentication-manager>
     * </code>
     * @author Rob Winch
     */
    @Configuration
    @EnableWebSecurity
    public static class SampleMultiHttpSecurityConfig {
        @Bean
        public AuthenticationManager authenticationManager() {
            return new AuthenticationBuilder()
                    .inMemoryAuthentication()
                        .withUser("user").password("password").roles("USER").and()
                        .withUser("admin").password("password").roles("USER", "ADMIN").and()
                        .and()
                    .build();
        }

        @Configuration
        public static class ApiWebSecurityConfigurationAdapater extends WebSecurityConfigurerAdapater {
            @Autowired
            private SampleMultiHttpSecurityConfig securityConfig;

            protected void authorizeUrls(ExpressionUrlAuthorizations interceptUrls) {
                interceptUrls
                    .antMatchers("/api/admin/**").hasRole("ADMIN")
                    .antMatchers("/api/**").hasRole("USER");
            }

            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .order(1)
                    .requestMatcher(new AntPathRequestMatcher("/api/**"))
                    .httpBasic();
            }

            protected AuthenticationManager authenticationManager(AuthenticationBuilder builder) {
                return securityConfig.authenticationManager();
            }
        }

        @Configuration
        public static class FormLoginWebSecurityConfigurerAdapater extends WebSecurityConfigurerAdapater {
            @Autowired
            private SampleMultiHttpSecurityConfig securityConfig;

            protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
                ignoredRequests
                    .antMatchers("/resources/**");
            }
            protected void authorizeUrls(ExpressionUrlAuthorizations interceptUrls) {
                interceptUrls
                    .antMatchers("/signup","/about").permitAll()
                    .antMatchers("/**").hasRole("USER");
            }

            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .formLogin()
                        .permitAll();
            }

            protected AuthenticationManager authenticationManager(AuthenticationBuilder builder) {
                return securityConfig.authenticationManager();
            }
        }
    }
}

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


import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*;
import static org.springframework.security.config.annotation.web.WebSecurityConfigurators.*;
import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

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
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder
import org.springframework.security.config.annotation.web.FormLoginSecurityFilterConfiguratorTests.FormLoginConfig
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
public class SampleSimpleWebSecurityConfigTests extends BaseWebSpecuritySpec {
    def "README Sample works"() {
        setup:
        loadConfig(SampleSimpleWebSecurityConfig)
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
    public static class SampleSimpleWebSecurityConfig extends SimpleWebSecurityConfig {
        protected FilterChainProxySecurityBuilder configure(
                FilterChainProxySecurityBuilder securityFilterChains) {
            return securityFilterChains
                // spring security ignores these URLs
                .ignoring(antMatchers("/resources/**"))
        }

        protected ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder filterInvocationBuilder() {
            return interceptUrls()
                .antMatchers("/signup","/about").permitAll()
                .antMatchers("/**").hasRole("USER");
        }

        protected SecurityFilterChainSecurityBuilder configure(
                SecurityFilterChainSecurityBuilder springSecurityFilterChain) {
            return springSecurityFilterChain
                .apply(formLogin()
                    // ensure the URLs for login are publicly accessible
                    .permitAll());
        }

        protected AuthenticationManager authenticationMgr() throws Exception {
            return inMemoryAuthentication(
                user("user").password("password").roles("USER"),
                user("admin").password("password").roles("USER", "ADMIN")
            ).authenticationManager();
        }
    }
}

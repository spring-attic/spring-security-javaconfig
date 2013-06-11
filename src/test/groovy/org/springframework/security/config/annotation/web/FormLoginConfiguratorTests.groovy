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
package org.springframework.security.config.annotation.web

import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.security.web.session.SessionManagementFilter
import org.springframework.security.web.util.AnyRequestMatcher
import org.springframework.test.util.ReflectionTestUtils

/**
 *
 * @author Rob Winch
 */
class FormLoginConfiguratorTests extends BaseSpringSpec {
    def "Form Login"() {
        when: "load formLogin()"
            context = new AnnotationConfigApplicationContext(FormLoginConfig)

        then: "FilterChains configured correctly"
            def filterChains = filterChains()
            filterChains.size() == 2
            filterChains[0].requestMatcher.pattern == '/resources/**'
            filterChains[0].filters.empty
            filterChains[1].requestMatcher instanceof AnyRequestMatcher
            filterChains[1].filters.collect { it.class.name.contains('$') ? it.class.superclass : it.class } ==
                    [SecurityContextPersistenceFilter, LogoutFilter, UsernamePasswordAuthenticationFilter,
                     RequestCacheAwareFilter, SecurityContextHolderAwareRequestFilter,
                     AnonymousAuthenticationFilter, SessionManagementFilter, ExceptionTranslationFilter, FilterSecurityInterceptor ]

        and: "UsernamePasswordAuthentictionFilter is configured correctly"
            UsernamePasswordAuthenticationFilter authFilter = findFilter(UsernamePasswordAuthenticationFilter,1)
            authFilter.usernameParameter == "username"
            authFilter.passwordParameter == "password"
            authFilter.failureHandler.defaultFailureUrl == "/login?error"
            authFilter.successHandler.defaultTargetUrl == "/"
            authFilter.requiresAuthentication(new MockHttpServletRequest(requestURI : "/login", method: "POST"), new MockHttpServletResponse())
            !authFilter.requiresAuthentication(new MockHttpServletRequest(requestURI : "/login", method: "GET"), new MockHttpServletResponse())

        and: "SessionFixationProtectionStrategy is configured correctly"
            SessionFixationProtectionStrategy sessionStrategy = ReflectionTestUtils.getField(authFilter,"sessionStrategy")
            sessionStrategy.migrateSessionAttributes

        and: "Exception handling is configured correctly"
            AuthenticationEntryPoint authEntryPoint = filterChains[1].filters.find { it instanceof ExceptionTranslationFilter}.authenticationEntryPoint
            MockHttpServletResponse response = new MockHttpServletResponse()
            authEntryPoint.commence(new MockHttpServletRequest(requestURI: "/private/"), response, new BadCredentialsException(""))
            response.redirectedUrl == "http://localhost/login"
    }

    @Configuration
    @EnableWebSecurity
    static class FormLoginConfig extends BaseWebConfig {
        @Override
        public void configure(WebSecurityBuilder builder)	throws Exception {
            builder
                .ignoring()
                    .antMatchers("/resources/**");
        }

        @Override
        protected void configure(HttpConfiguration http) {
            http
                .authorizeUrls()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .loginUrl("/login")
        }
    }

    def "FormLogin.permitAll()"() {
        when: "load formLogin() with permitAll"
            context = new AnnotationConfigApplicationContext(FormLoginConfigPermitAll)

        then: "the formLogin URLs are granted access"
            FilterChainProxy filterChain = context.getBean(FilterChainProxy)
            MockHttpServletResponse response = new MockHttpServletResponse()
            filterChain.doFilter(new MockHttpServletRequest(servletPath : servletPath, requestURI: servletPath, queryString: query, method: method), response, new MockFilterChain())
            response.redirectedUrl == redirectUrl

        where:
            servletPath | method | query | redirectUrl
            "/login" | "GET" | null | null
            "/login" | "POST" | null | "/login?error"
            "/login" | "GET" | "error" | null
    }

    @Configuration
    @EnableWebSecurity
    static class FormLoginConfigPermitAll extends BaseWebConfig {

        @Override
        protected void configure(HttpConfiguration http) {
            http
                .authorizeUrls()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .permitAll()
        }
    }

    def "formLogin LifecycleManager"() {
        setup: "initialize the AUTH_FILTER as a mock"
            LifecycleManager lifecycleManager = Mock(LifecycleManager)
            HttpConfiguration http = new HttpConfiguration(lifecycleManager, authenticationBldr)
        when:
            http
                .formLogin()
                    .and()
                .build()

        then: "UsernamePasswordAuthenticationFilter is registered with LifecycleManager"
            1 * lifecycleManager.registerLifecycle(_ as UsernamePasswordAuthenticationFilter)
        and: "LoginUrlAuthenticationEntryPoint is registered with LifecycleManager"
            1 * lifecycleManager.registerLifecycle(_ as LoginUrlAuthenticationEntryPoint)
    }
}

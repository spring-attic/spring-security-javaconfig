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
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.AnyRequestMatcher
import org.springframework.test.util.ReflectionTestUtils;

/**
 *
 * @author Rob Winch
 */
class FormLoginSecurityFilterConfiguratorTests extends BaseSpringSpec {
    def "Form Login"() {
        when:
        context = new AnnotationConfigApplicationContext(FormLoginConfig)
        then:
        List<DefaultSecurityFilterChain> filterChains = context.getBean(FilterChainProxy).filterChains
        filterChains.size() == 2
        filterChains[0].requestMatcher.pattern == '/resources/**'
        filterChains[0].filters.empty
        filterChains[1].requestMatcher instanceof AnyRequestMatcher
        filterChains[1].filters.collect { it.class.name.contains('$') ? it.class.superclass : it.class } ==
                [SecurityContextPersistenceFilter, LogoutFilter, UsernamePasswordAuthenticationFilter,
                 RequestCacheAwareFilter, SecurityContextHolderAwareRequestFilter,
                 AnonymousAuthenticationFilter, SessionManagementFilter, ExceptionTranslationFilter, FilterSecurityInterceptor ]
        UsernamePasswordAuthenticationFilter authFilter = filterChains[1].filters.find { it instanceof UsernamePasswordAuthenticationFilter}
        authFilter.usernameParameter == "username"
        authFilter.passwordParameter == "password"
        authFilter.failureHandler.defaultFailureUrl == "/login?error"
        authFilter.successHandler.defaultTargetUrl == "/"
        SessionFixationProtectionStrategy sessionStrategy = ReflectionTestUtils.getField(authFilter,"sessionStrategy")
        sessionStrategy.migrateSessionAttributes
        authFilter.requiresAuthentication(new MockHttpServletRequest(requestURI : "/login", method: "POST"), new MockHttpServletResponse())
        !authFilter.requiresAuthentication(new MockHttpServletRequest(requestURI : "/login", method: "GET"), new MockHttpServletResponse())

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
                    .antMatchers("/**").hasRole("USER")
                    .and()
                .formLogin()
                    .loginUrl("/login")
        }
    }

    def "FormLogin.permitAll()"() {
        when:
        context = new AnnotationConfigApplicationContext(FormLoginConfigPermitAll)
        then:
        FilterChainProxy filterChain = context.getBean(FilterChainProxy)

        expect:
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
                    .antMatchers("/**").hasRole("USER")
                    .and()
                .formLogin()
                    .permitAll()
        }
    }
}

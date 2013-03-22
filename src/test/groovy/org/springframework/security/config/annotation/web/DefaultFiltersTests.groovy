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
package org.springframework.security.config.annotation.web

import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

import java.util.List;

import org.springframework.beans.factory.BeanCreationException
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.config.annotation.BaseSpringSpec;
import org.springframework.security.config.annotation.web.ExceptionHandlingConfigurator;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder;
import org.springframework.security.config.annotation.web.UrlAuthorizationRegistry;
import org.springframework.security.config.annotation.web.FormLoginSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.HttpConfiguration;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder;
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.AnyRequestMatcher
import org.springframework.security.web.util.RequestMatcher;

import spock.lang.AutoCleanup
import spock.lang.Specification

/**
 *
 * @author Rob Winch
 */
class DefaultFiltersTests extends BaseSpringSpec {

    def "DefaultSecurityFilterChainBuilder cannot be null"() {
        when:
        context = new AnnotationConfigApplicationContext(FilterChainProxyBuilderMissingConfig)
        then:
        BeanCreationException e = thrown()
        e.message.contains "At least one non-null instance of WebSecurityConfigurerAdapater must be exposed as a @Bean when using @EnableWebSecurity"
    }

    @Configuration
    @EnableWebSecurity
    static class FilterChainProxyBuilderMissingConfig { }

    def "FilterChainProxyBuilder no DefaultSecurityFilterChainBuilder specified"() {
        when:
        context = new AnnotationConfigApplicationContext(FilterChainProxyBuilderNoSecurityFilterBuildersConfig)
        then:
        BeanCreationException e = thrown()
        e.message.contains "At least one non-null instance of WebSecurityConfigurerAdapater must be exposed as a @Bean when using @EnableWebSecurity"
    }

    @Configuration
    @EnableWebSecurity
    static class FilterChainProxyBuilderNoSecurityFilterBuildersConfig {
        @Bean
        public SpringSecurityFilterChainBuilder filterChainProxyBuilder() {
            new SpringSecurityFilterChainBuilder()
                .ignoring(antMatchers("/resources/**"))
        }
    }

    def "null WebInvocationPrivilegeEvaluator"() {
        when:
        context = new AnnotationConfigApplicationContext(NullWebInvocationPrivilegeEvaluatorConfig)
        then:
        List<DefaultSecurityFilterChain> filterChains = context.getBean(FilterChainProxy).filterChains
        filterChains.size() == 1
        filterChains[0].requestMatcher instanceof AnyRequestMatcher
        filterChains[0].filters.size() == 1
        filterChains[0].filters.find { it instanceof UsernamePasswordAuthenticationFilter }
    }

    @Configuration
    @EnableWebSecurity
    static class NullWebInvocationPrivilegeEvaluatorConfig extends BaseWebConfig {
        protected void configure(
                HttpConfiguration springSecurityFilterChain) {
            springSecurityFilterChain.formLogin()
        }

        @Override
        protected void applyDefaults(HttpConfiguration builder)
                throws Exception {
        }
    }

    def "FilterChainProxyBuilder ignoring resources"() {
        when:
        context = new AnnotationConfigApplicationContext(FilterChainProxyBuilderIgnoringConfig)
        then:
        List<DefaultSecurityFilterChain> filterChains = context.getBean(FilterChainProxy).filterChains
        filterChains.size() == 2
        filterChains[0].requestMatcher.pattern == '/resources/**'
        filterChains[0].filters.empty
        filterChains[1].requestMatcher instanceof AnyRequestMatcher
        filterChains[1].filters.collect { it.class } ==
                [SecurityContextPersistenceFilter, LogoutFilter, RequestCacheAwareFilter,
                 SecurityContextHolderAwareRequestFilter, AnonymousAuthenticationFilter, SessionManagementFilter,
                 ExceptionTranslationFilter, FilterSecurityInterceptor ]
    }

    @Configuration
    @EnableWebSecurity
    static class FilterChainProxyBuilderIgnoringConfig extends BaseWebConfig {
        public List<RequestMatcher> ignoredRequests() {
            return antMatchers("/resources/**")
        }
        protected void configure(
                HttpConfiguration springSecurityFilterChain) {
        }
    }

   def "DefaultFilters.permitAll()"() {
        when:
        context = new AnnotationConfigApplicationContext(DefaultFiltersConfigPermitAll)
        then:
        FilterChainProxy filterChain = context.getBean(FilterChainProxy)

        expect:
        MockHttpServletResponse response = new MockHttpServletResponse()
        filterChain.doFilter(new MockHttpServletRequest(servletPath : uri, queryString: query), response, new MockFilterChain())
        response.redirectedUrl == null
        where:
        uri | query
        "/logout" | null
    }

    @Configuration
    @EnableWebSecurity
    static class DefaultFiltersConfigPermitAll extends BaseWebConfig {
        public List<RequestMatcher> ignoredRequests() {
            return antMatchers("/resources/**")
        }
        protected void configure(
                HttpConfiguration springSecurityFilterChain) {
        }
    }
}



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

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
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
 * Tests to verify that all the functionality of <anonymous> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpFormLoginTests extends BaseSpringSpec {
    FilterChainProxy springSecurityFilterChain
    MockHttpServletRequest request
    MockHttpServletResponse response
    MockFilterChain chain

    def setup() {
        request = new MockHttpServletRequest()
        response = new MockHttpServletResponse()
        chain = new MockFilterChain()
    }

    def "http/form-login"() {
        setup:
        loadConfig(FormLoginConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.getRedirectedUrl() == "http://localhost/login"
        when: "fail to log in"
        setup()
        request.requestURI = "/login"
        request.method = "POST"
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
        response.getRedirectedUrl() == "/login?error"
        when: "login success"
        setup()
        request.requestURI = "/login"
        request.method = "POST"
        request.parameters.username = ["user"] as String[]
        request.parameters.password = ["password"] as String[]
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default succes page"
        response.getRedirectedUrl() == "/"
    }

    @Configuration
    static class FormLoginConfig extends BaseWebConfig {

        @Override
        public void configure(WebSecurityConfiguration builder) throws Exception {
            builder
                .ignoring()
                    .antMatchers("/resources/**");
        }

        @Override
        protected void configure(HttpConfigurator http) {
            http
                .authorizeUrls()
                    .antMatchers("/**").hasRole("USER")
                    .and()
                .formLogin()
        }
    }

    def "http/form-login custom"() {
        setup:
        loadConfig(FormLoginCustomConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.getRedirectedUrl() == "http://localhost/authentication/login"
        when: "fail to log in"
        setup()
        request.requestURI = "/authentication/login/process"
        request.method = "POST"
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
        response.getRedirectedUrl() == "/authentication/login?failed"
        when: "login success"
        setup()
        request.requestURI = "/authentication/login/process"
        request.method = "POST"
        request.parameters.j_username = ["user"] as String[]
        request.parameters.j_password = ["password"] as String[]
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default succes page"
        response.getRedirectedUrl() == "/default"
    }

    @Configuration
    static class FormLoginCustomConfig extends BaseWebConfig {
        protected void configure(HttpConfigurator http) throws Exception {
            boolean alwaysUseDefaultSuccess = true;
            http
                .authorizeUrls()
                    .antMatchers("/**").hasRole("USER")
                    .and()
                .formLogin()
                    .usernameParameter("j_username") // form-login@username-parameter
                    .passwordParameter("j_password") // form-login@password-parameter
                    .loginPage("/authentication/login") // form-login@login-page
                    .failureUrl("/authentication/login?failed") // form-login@authentication-failure-url
                    .loginProcessingUrl("/authentication/login/process") // form-login@login-processing-url
                    .defaultSuccessUrl("/default", alwaysUseDefaultSuccess) // form-login@default-target-url / form-login@always-use-default-target
        }
    }

    def "http/form-login custom refs"() {
        when:
        loadConfig(FormLoginCustomRefsConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        then: "CustomWebAuthenticationDetailsSource is used"
        findFilter(UsernamePasswordAuthenticationFilter).authenticationDetailsSource.class == CustomWebAuthenticationDetailsSource
        when: "fail to log in"
        request.requestURI = "/login"
        request.method = "POST"
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
        response.getRedirectedUrl() == "/custom/failure"
        when: "login success"
        setup()
        request.requestURI = "/login"
        request.method = "POST"
        request.parameters.username = ["user"] as String[]
        request.parameters.password = ["password"] as String[]
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default succes page"
        response.getRedirectedUrl() == "/custom/targetUrl"
    }

    @Configuration
    static class FormLoginCustomRefsConfig extends BaseWebConfig {
        protected void configure(HttpConfigurator http) throws Exception {
            http
                .formLogin()
                    .failureHandler(new SimpleUrlAuthenticationFailureHandler("/custom/failure")) // form-login@authentication-failure-handler-ref
                    .successHandler(new SavedRequestAwareAuthenticationSuccessHandler( defaultTargetUrl : "/custom/targetUrl" )) // form-login@authentication-success-handler-ref
                    .authenticationDetailsSource(new CustomWebAuthenticationDetailsSource()) // form-login@authentication-details-source-ref
                    .and();
        }
    }

    static class CustomWebAuthenticationDetailsSource extends WebAuthenticationDetailsSource {}
}

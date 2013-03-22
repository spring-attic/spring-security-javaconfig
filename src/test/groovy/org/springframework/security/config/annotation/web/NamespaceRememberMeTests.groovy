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
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext
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
import org.springframework.security.web.context.HttpRequestResponseHolder
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
public class NamespaceRememberMeTests extends BaseSpringSpec {
    FilterChainProxy springSecurityFilterChain
    MockHttpServletRequest request
    MockHttpServletResponse response
    MockFilterChain chain

    def setup() {
        request = new MockHttpServletRequest()
        response = new MockHttpServletResponse()
        chain = new MockFilterChain()
    }

    def "http/remember-me"() {
        setup:
            loadConfig(RememberMeConfig)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
        when: "login with remember me"
            setup()
            request.requestURI = "/login"
            request.method = "POST"
            request.parameters.username = ["user"] as String[]
            request.parameters.password = ["password"] as String[]
            request.parameters.'remember-me' = ["true"] as String[]
            springSecurityFilterChain.doFilter(request,response,chain)
            Cookie rememberMeCookie = getRememberMeCookie()
        then: "response contains remember me cookie"
            rememberMeCookie != null
        when: "session expires"
            setup()
            request.setCookies(rememberMeCookie)
            request.requestURI = "/abc"
            springSecurityFilterChain.doFilter(request,response,chain)
            MockHttpSession session = request.getSession()
        then: "initialized to RememberMeAuthenticationToken"
            SecurityContext context = new HttpSessionSecurityContextRepository().loadContext(new HttpRequestResponseHolder(request, response))
            context.getAuthentication() instanceof RememberMeAuthenticationToken
        when: "logout"
            setup()
            request.setSession(session)
            request.setCookies(rememberMeCookie)
            request.requestURI = "/logout"
            springSecurityFilterChain.doFilter(request,response,chain)
            rememberMeCookie = getRememberMeCookie()
        then: "logout cookie expired"
            response.getRedirectedUrl() == "/login?logout"
            rememberMeCookie.maxAge == 0
        when: "use remember me after logout"
            setup()
            request.setCookies(rememberMeCookie)
            request.requestURI = "/abc"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to default login page"
            response.getRedirectedUrl() == "http://localhost/login"
    }

    @Configuration
    static class RememberMeConfig extends BaseWebConfig {
        protected void configure(
                HttpConfiguration springSecurityFilterChain) {
                springSecurityFilterChain
                    .formLogin()
                        .and()
                    .rememberMe()
        }
    }

    Cookie getRememberMeCookie(String cookieName="remember-me") {
        response.getCookie(cookieName)
    }
}

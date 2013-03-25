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

import java.io.IOException;

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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.codec.Base64;
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
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedException;
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
public class NamespaceHttpFirewallTests extends BaseSpringSpec {
    FilterChainProxy springSecurityFilterChain
    MockHttpServletRequest request
    MockHttpServletResponse response
    MockFilterChain chain

    def setup() {
        request = new MockHttpServletRequest()
        response = new MockHttpServletResponse()
        chain = new MockFilterChain()
    }

    def "http-firewall"() {
        setup:
        loadConfig(HttpFirewallConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        request.setPathInfo("/public/../private/")
        when:
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "the default firewall is used"
        thrown(RequestRejectedException)
    }

    @Configuration
    static class HttpFirewallConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) {
        }
    }

    def "http-firewall@ref"() {
        setup:
        loadConfig(CustomHttpFirewallConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        request.setParameter("deny", "true")
        when:
        springSecurityFilterChain.doFilter(request,response,chain)
        then: "the custom firewall is used"
        thrown(RequestRejectedException)
    }

    @Configuration
    static class CustomHttpFirewallConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) {
        }
        protected void performConfigure(
                SpringSecurityFilterChainBuilder springSecurityFilterChain) {
            springSecurityFilterChain.httpFirewall(new CustomHttpFirewall())
        }
    }

    static class CustomHttpFirewall extends DefaultHttpFirewall {

        @Override
        public FirewalledRequest getFirewalledRequest(HttpServletRequest request)
                throws RequestRejectedException {
            if(request.getParameter("deny")) {
                throw new RequestRejectedException("custom rejection")
            }
            return super.getFirewalledRequest(request)
        }

        @Override
        public HttpServletResponse getFirewalledResponse(
                HttpServletResponse response) {
            return super.getFirewalledRequest(response)
        }

    }
}

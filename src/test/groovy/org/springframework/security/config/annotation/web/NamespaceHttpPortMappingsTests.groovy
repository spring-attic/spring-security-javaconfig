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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.EnableMBeanExport;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseAuthenticationConfig;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextImpl;
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
import org.springframework.security.web.context.HttpRequestResponseHolder
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
 * Tests to verify that all the functionality of <port-mappings> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpPortMappingsTests extends BaseSpringSpec {
    FilterChainProxy springSecurityFilterChain
    MockHttpServletRequest request
    MockHttpServletResponse response
    MockFilterChain chain

    def setup() {
        request = new MockHttpServletRequest()
        request.setMethod("GET")
        response = new MockHttpServletResponse()
        chain = new MockFilterChain()
    }

    def "http/port-mapper works with http/intercept-url@requires-channel"() {
        setup:
            loadConfig(HttpInterceptUrlWithPortMapperConfig)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
            request.setServletPath("/login")
            request.setRequestURI("/login")
            request.setServerPort(9080);
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.redirectedUrl == "https://localhost:9443/login"
        when:
            setup()
            request.setServletPath("/secured/a")
            request.setRequestURI("/secured/a")
            request.setServerPort(9080);
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.redirectedUrl == "https://localhost:9443/secured/a"
        when:
            setup()
            request.setSecure(true)
            request.setScheme("https")
            request.setServerPort(9443);
            request.setServletPath("/user")
            request.setRequestURI("/user")
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.redirectedUrl == "http://localhost:9080/user"
    }

    @Configuration
    @EnableWebSecurity
    static class HttpInterceptUrlWithPortMapperConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpConfigurator http) throws Exception {
            http
                .authorizeUrls()
                    .antMatchers("/**").hasRole("USER")
                    .and()
                .portMapper()
                    .http(9080).mapsTo(9443)
                    .and()
                .requiresChannel()
                    .antMatchers("/login","/secured/**").requiresSecure()
                    .antMatchers("/**").requiresInsecure()
        }

        protected void registerAuthentication(
                AuthenticationRegistry authenticationRegistry) throws Exception {
            authenticationRegistry
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN")
        }
    }

    def login(String username="user", String role="ROLE_USER") {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository()
        HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(request, response)
        repo.loadContext(requestResponseHolder)
        repo.saveContext(new SecurityContextImpl(authentication: new UsernamePasswordAuthenticationToken(username, null, AuthorityUtils.createAuthorityList(role))), requestResponseHolder.request, requestResponseHolder.response)
    }
}

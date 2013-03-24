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
 * Tests to verify that all the functionality of <intercept-url> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpInterceptUrlTests extends BaseSpringSpec {
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

    def "http/intercept-url denied when not logged in"() {
        setup:
        loadConfig(HttpInterceptUrlConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        request.servletPath == "/users"
        when:
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.status == HttpServletResponse.SC_FORBIDDEN
    }

    def "http/intercept-url denied when logged in"() {
        setup:
        loadConfig(HttpInterceptUrlConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        login()
        request.setServletPath("/users")
        when:
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.status == HttpServletResponse.SC_FORBIDDEN
    }

    def "http/intercept-url allowed when logged in"() {
        setup:
        loadConfig(HttpInterceptUrlConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        login("admin","ROLE_ADMIN")
        request.setServletPath("/users")
        when:
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.status == HttpServletResponse.SC_OK
        !response.isCommitted()
    }

    def "http/intercept-url@method=POST"() {
        setup:
        loadConfig(HttpInterceptUrlConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
        login()
        request.setServletPath("/admin/post")
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.status == HttpServletResponse.SC_OK
        !response.isCommitted()
        when:
        setup()
        login()
        request.setServletPath("/admin/post")
        request.setMethod("POST")
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.status == HttpServletResponse.SC_FORBIDDEN
        when:
        setup()
        login("admin","ROLE_ADMIN")
        request.setServletPath("/admin/post")
        request.setMethod("POST")
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.status == HttpServletResponse.SC_OK
        !response.committed
    }

    def "http/intercept-url@requires-channel"() {
        setup:
        loadConfig(HttpInterceptUrlConfig)
        springSecurityFilterChain = context.getBean(FilterChainProxy)
        when:
        request.setServletPath("/login")
        request.setRequestURI("/login")
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.redirectedUrl == "https://localhost/login"
        when:
        setup()
        request.setServletPath("/secured/a")
        request.setRequestURI("/secured/a")
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.redirectedUrl == "https://localhost/secured/a"
        when:
        setup()
        request.setSecure(true)
        request.setScheme("https")
        request.setServletPath("/user")
        request.setRequestURI("/user")
        springSecurityFilterChain.doFilter(request,response,chain)
        then:
        response.redirectedUrl == "http://localhost/user"
    }

    // TODO add support for port-mapper

    @Configuration
    @EnableWebSecurity
    static class HttpInterceptUrlConfig extends WebSecurityConfigurerAdapater {
        @Override
        protected void authorizeUrls(
                ExpressionUrlAuthorizations interceptUrls) {
             interceptUrls
                // the line below is similar to intercept-url@pattern:
                //    <intercept-url pattern="/users**" access="hasRole('ROLE_ADMIN')"/>
                //    <intercept-url pattern="/sessions/**" access="hasRole('ROLE_ADMIN')"/>
                .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
                // the line below is similar to intercept-url@method:
                //    <intercept-url pattern="/admin/post" access="hasRole('ROLE_ADMIN')" method="POST"/>
                //    <intercept-url pattern="/admin/another-post/**" access="hasRole('ROLE_ADMIN')" method="POST"/>
                .antMatchers(HttpMethod.POST, "/admin/post","/admin/another-post/**").hasRole("ADMIN")
                .antMatchers("/signup").permitAll()
                .antMatchers("/**").hasRole("USER");
        }

        protected void configure(HttpConfiguration http) throws Exception {
            http
                .requiresChannel()
                    // NOTE: channel security is configured separately of authorization (i.e. intercept-url@access
                    // the line below is similar to intercept-url@requires-channel="https":
                    //    <intercept-url pattern="/login" requires-channel="https"/>
                    //    <intercept-url pattern="/secured/**" requires-channel="https"/>
                    .antMatchers("/login","/secured/**").requiresSecure()
                    // the line below is similar to intercept-url@requires-channel="http":
                    //    <intercept-url pattern="/**" requires-channel="http"/>
                    .antMatchers("/**").requiresInsecure()
        }
        protected AuthenticationManager authenticationManager(
                AuthenticationRegistry authenticationRegistry) throws Exception {
            authenticationRegistry
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN").and()
                    .and()
                .build()
        }
    }

    def login(String username="user", String role="ROLE_USER") {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository()
        HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(request, response)
        repo.loadContext(requestResponseHolder)
        repo.saveContext(new SecurityContextImpl(authentication: new UsernamePasswordAuthenticationToken(username, null, AuthorityUtils.createAuthorityList(role))), requestResponseHolder.request, requestResponseHolder.response)
    }
}



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
import org.springframework.security.openid.OpenID4JavaConsumer;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
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
 * Tests to verify that all the functionality of <openid-login> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpOpenIDLoginTests extends BaseSpringSpec {
    FilterChainProxy springSecurityFilterChain
    MockHttpServletRequest request
    MockHttpServletResponse response
    MockFilterChain chain

    def setup() {
        request = new MockHttpServletRequest()
        response = new MockHttpServletResponse()
        chain = new MockFilterChain()
    }

    def "http/openid-login"() {
        when:
            loadConfig(OpenIDLoginConfig)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
        then:
            findFilter(OpenIDAuthenticationFilter).consumer.class == OpenID4JavaConsumer
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.getRedirectedUrl() == "http://localhost/login"
        when: "fail to log in"
            setup()
            request.requestURI = "/login/openid"
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
            response.getRedirectedUrl() == "/login?error"
    }

    @Configuration
    static class OpenIDLoginConfig extends BaseWebConfig {
        protected void configure(HttpConfigurator http) {
            http
                .openidLogin()
                    .permitAll();
        }
    }

    def "http/openid-login/attribute-exchange"() {
        when:
            loadConfig(OpenIDLoginAttributeExchangeConfig)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
            OpenID4JavaConsumer consumer = findFilter(OpenIDAuthenticationFilter).consumer
        then:
            consumer.class == OpenID4JavaConsumer

            def googleAttrs = consumer.attributesToFetchFactory.createAttributeList("https://www.google.com/1")
            googleAttrs[0].name == "email"
            googleAttrs[0].type == "http://axschema.org/contact/email"
            googleAttrs[0].required
            googleAttrs[1].name == "firstname"
            googleAttrs[1].type == "http://axschema.org/namePerson/first"
            googleAttrs[1].required
            googleAttrs[2].name == "lastname"
            googleAttrs[2].type == "http://axschema.org/namePerson/last"
            googleAttrs[2].required

            def yahooAttrs = consumer.attributesToFetchFactory.createAttributeList("https://rwinch.yahoo.com/rwinch/id")
            yahooAttrs[0].name == "email"
            yahooAttrs[0].type == "http://schema.openid.net/contact/email"
            yahooAttrs[0].required
            yahooAttrs[1].name == "fullname"
            yahooAttrs[1].type == "http://axschema.org/namePerson"
            yahooAttrs[1].required
        when:
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            response.getRedirectedUrl() == "http://localhost/login"
        when: "fail to log in"
            setup()
            request.requestURI = "/login/openid"
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
            response.getRedirectedUrl() == "/login?error"
    }

    @Configuration
    static class OpenIDLoginAttributeExchangeConfig extends BaseWebConfig {
        protected void configure(HttpConfigurator http) {
            http
                .openidLogin()
                    .attributeExchange("https://www.google.com/.*")
                        .attribute("email")
                            .type("http://axschema.org/contact/email")
                            .required(true)
                            .and()
                        .attribute("firstname")
                            .type("http://axschema.org/namePerson/first")
                            .required(true)
                            .and()
                        .attribute("lastname")
                            .type("http://axschema.org/namePerson/last")
                            .required(true)
                            .and()
                        .and()
                    .attributeExchange(".*yahoo.com.*")
                        .attribute("email")
                            .type("http://schema.openid.net/contact/email")
                            .required(true)
                            .and()
                        .attribute("fullname")
                            .type("http://axschema.org/namePerson")
                            .required(true)
                            .and()
                        .and()
                    .permitAll();
        }
    }

    def "http/openid-login custom"() {
        setup:
            loadConfig(OpenIDLoginCustomConfig)
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
    }

    @Configuration
    static class OpenIDLoginCustomConfig extends BaseWebConfig {
        protected void configure(HttpConfigurator http) throws Exception {
            boolean alwaysUseDefaultSuccess = true;
            http
                .openidLogin()
                    .permitAll()
                    .loginPage("/authentication/login") // openid-login@login-page
                    .failureUrl("/authentication/login?failed") // openid-login@authentication-failure-url
                    .loginProcessingUrl("/authentication/login/process") // openid-login@login-processing-url
                    .defaultSuccessUrl("/default", alwaysUseDefaultSuccess) // openid-login@default-target-url / form-login@always-use-default-target
        }
    }

    def "http/openid-login custom refs"() {
        when:
            loadConfig(OpenIDLoginCustomRefsConfig)
            springSecurityFilterChain = context.getBean(FilterChainProxy)
        then: "CustomWebAuthenticationDetailsSource is used"
            findFilter(OpenIDAuthenticationFilter).authenticationDetailsSource.class == CustomWebAuthenticationDetailsSource
        when: "fail to log in"
            request.requestURI = "/login/openid"
            request.method = "POST"
            springSecurityFilterChain.doFilter(request,response,chain)
        then: "sent to login error page"
            response.getRedirectedUrl() == "/custom/failure"
    }

    @Configuration
    static class OpenIDLoginCustomRefsConfig extends BaseWebConfig {
        protected void configure(HttpConfigurator http) throws Exception {
            http
                .openidLogin()
                    .failureHandler(new SimpleUrlAuthenticationFailureHandler("/custom/failure")) // openid-login@authentication-failure-handler-ref
                    .successHandler(new SavedRequestAwareAuthenticationSuccessHandler( defaultTargetUrl : "/custom/targetUrl" )) // openid-login@authentication-success-handler-ref
                    .authenticationDetailsSource(new CustomWebAuthenticationDetailsSource()); // openid-login@authentication-details-source-ref
        }
    }

    static class CustomWebAuthenticationDetailsSource extends WebAuthenticationDetailsSource {}
}

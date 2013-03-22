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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.OrderComparator;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
@Configuration
public class WebSecurityConfiguration {
    @Autowired(required = false)
    private WebSecurityConfigurerAdapater[] webSecurityConfigurerAdapaters;

    @Bean
    public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
        return new DefaultWebSecurityExpressionHandler();
    }

    @Bean
    public FilterChainProxy springSecurityFilterChain() throws Exception {
        SpringSecurityFilterChainBuilder springSecurityFilterChainBuilder = springSecurityFilterChainBuilder();
        return springSecurityFilterChainBuilder.build();
    }

    @Bean
    public SpringSecurityFilterChainBuilder springSecurityFilterChainBuilder() throws Exception {
        SpringSecurityFilterChainBuilder springSecurityFilterChain = new SpringSecurityFilterChainBuilder()
            .securityFilterChains(filterChainBuilders())
            .ignoring(requestToIgnore());
        for(WebSecurityConfigurerAdapater adapater : webSecurityConfiguredAdapters()) {
            adapater.configure(springSecurityFilterChain);
        }
        return springSecurityFilterChain;
    }

    /**
     * @return
     */
    private List<? extends RequestMatcher> requestToIgnore() {
        List<RequestMatcher> result = new ArrayList<RequestMatcher>();
        for(WebSecurityConfigurerAdapater adapter : webSecurityConfiguredAdapters()) {
            result.addAll(adapter.ignoredRequests());
        }
        return result;
    }

    @Bean(name=BeanIds.AUTHENTICATION_MANAGER)
    public AuthenticationManager authenticationManager() throws Exception {
        for(WebSecurityConfigurerAdapater adapter : webSecurityConfiguredAdapters()) {
            AuthenticationManager authenticationManager = adapter.authenticationManager();
            if(authenticationManager != null) {
                return authenticationManager;
            }
        }
        return null;
    }

    @Bean(name=BeanIds.USER_DETAILS_SERVICE)
    public UserDetailsService userDetailsService() throws Exception {
        for(WebSecurityConfigurerAdapater adapter : webSecurityConfiguredAdapters()) {
            UserDetailsService userDetailsService = adapter.userDetailsService();
            if(userDetailsService != null) {
                return userDetailsService;
            }
        }
        return null;
    }

    @Bean
    public WebInvocationPrivilegeEvaluator privilegeEvaluator() throws Exception {
        FilterSecurityInterceptor securityInterceptor = springSecurityFilterChainBuilder().securityInterceptor();
        return securityInterceptor == null ? null : new DefaultWebInvocationPrivilegeEvaluator(securityInterceptor);
    }

    private HttpConfiguration[] filterChainBuilders() throws Exception {
        HttpConfiguration[] result = new HttpConfiguration[webSecurityConfiguredAdapters().length];
        for(int i=0;i<webSecurityConfigurerAdapaters.length;i++) {
            result[i] = webSecurityConfigurerAdapaters[i].defaultSecurityFilterChainBuilder();
        }
        Arrays.sort(result,OrderComparator.INSTANCE);
        return result;
    }

    private WebSecurityConfigurerAdapater[] webSecurityConfiguredAdapters() {
        Assert.state(webSecurityConfigurerAdapaters != null, "At least one non-null instance of WebSecurityConfigurerAdapater must be exposed as a @Bean when using @EnableWebSecurity");
        return webSecurityConfigurerAdapaters;
    }
}

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

import java.util.Arrays;

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
import org.springframework.util.Assert;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
@Configuration
public class WebSecurityConfiguration {
    @Autowired(required = false)
    private WebSecurityConfigurer[] webSecurityConfigurers;

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
            .securityFilterChains(httpBuilders());
        for(WebSecurityConfigurer adapater : webSecurityConfigurers()) {
            adapater.configure(springSecurityFilterChain);
        }
        return springSecurityFilterChain;
    }

    @Bean(name=BeanIds.AUTHENTICATION_MANAGER)
    public AuthenticationManager authenticationManager() throws Exception {
        for(WebSecurityConfigurer adapter : webSecurityConfigurers()) {
            AuthenticationManager authenticationManager = adapter.authenticationManager();
            if(authenticationManager != null) {
                return authenticationManager;
            }
        }
        return null;
    }

    @Bean(name=BeanIds.USER_DETAILS_SERVICE)
    public UserDetailsService userDetailsService() throws Exception {
        for(WebSecurityConfigurer adapter : webSecurityConfigurers()) {
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

    private HttpConfiguration[] httpBuilders() throws Exception {
        HttpConfiguration[] result = new HttpConfiguration[webSecurityConfigurers().length];
        for(int i=0;i<webSecurityConfigurers.length;i++) {
            result[i] = webSecurityConfigurers[i].httpConfiguration();
        }
        Arrays.sort(result,OrderComparator.INSTANCE);
        return result;
    }

    private WebSecurityConfigurer[] webSecurityConfigurers() {
        Assert.state(webSecurityConfigurers != null, "At least one non-null instance of WebSecurityConfigurer must be exposed as a @Bean when using @EnableWebSecurity");
        return webSecurityConfigurers;
    }
}

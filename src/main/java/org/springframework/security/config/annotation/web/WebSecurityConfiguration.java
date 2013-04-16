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

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.AbstractConfiguredBuilder;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
@Configuration
public class WebSecurityConfiguration extends AbstractConfiguredBuilder<FilterChainProxy, WebSecurityConfiguration> {
    private final SpringSecurityFilterChainBuilder springSecurityFilterChain = new SpringSecurityFilterChainBuilder();

    private List<WebSecurityConfigurer> webSecurityConfigurers;

    @Bean
    public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
        return new DefaultWebSecurityExpressionHandler();
    }

    @Bean(name="springSecurityFilterChain")
    public FilterChainProxy springSecurityFilterChain() throws Exception {
        return build();
    }

    @Bean(name=BeanIds.AUTHENTICATION_MANAGER)
    public AuthenticationManager authenticationManager() throws Exception {
        verifyhConfigurators();
        for(WebSecurityConfigurer webSecurityConfigurer : webSecurityConfigurers) {
            AuthenticationManager authenticationManager = webSecurityConfigurer.getAuthenticationManager();
            if(authenticationManager != null) {
                return authenticationManager;
            }
        }
        return null;
    }

    @Bean(name=BeanIds.USER_DETAILS_SERVICE)
    public UserDetailsService userDetailsService() throws Exception {
        verifyhConfigurators();
        for(WebSecurityConfigurer webSecurityConfigurer : webSecurityConfigurers) {
            UserDetailsService userDetailsService = webSecurityConfigurer.getUserDetailsService();
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

    @Autowired(required = false)
    public void setFilterChainProxySecurityConfigurator(
            List<WebSecurityConfigurer> webSecurityConfigurers) throws Exception {
        Collections.sort(webSecurityConfigurers,AnnotationAwareOrderComparator.INSTANCE);
        for(SecurityConfigurator<FilterChainProxy, WebSecurityConfiguration> webSecurityConfigurer : webSecurityConfigurers) {
            apply(webSecurityConfigurer);
        }
        this.webSecurityConfigurers = webSecurityConfigurers;
    }

    SpringSecurityFilterChainBuilder springSecurityFilterChainBuilder() throws Exception {
        return springSecurityFilterChain;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.AbstractSecurityBuilder#doBuild()
     */
    @Override
    protected FilterChainProxy doBuild() throws Exception {
        verifyhConfigurators();
        init();
        configure();
        return springSecurityFilterChain.build();
    }

    private void verifyhConfigurators() {
        boolean hasConfigurators = webSecurityConfigurers != null && !webSecurityConfigurers.isEmpty();
        if(!hasConfigurators) {
            throw new IllegalStateException("At least one non-null instance of WebSecurityConfigurerAdapater must be exposed as a @Bean when using @EnableWebSecurity");
        }
    }
}

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

import org.springframework.aop.TargetSource;
import org.springframework.aop.framework.ProxyFactoryBean;
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
    private ProxyFactoryBean authenticationManager = lazyBean(AuthenticationManager.class);

    private ProxyFactoryBean userDetailsService = lazyBean(UserDetailsService.class);

    private final SpringSecurityFilterChainBuilder springSecurityFilterChain = new SpringSecurityFilterChainBuilder();

    private boolean hasConfigurators;

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
        return (AuthenticationManager) authenticationManager.getObject();
    }

    @Bean(name=BeanIds.USER_DETAILS_SERVICE)
    public UserDetailsService userDetailsService() throws Exception {
        return (UserDetailsService) userDetailsService.getObject();
    }

    @Bean
    public WebInvocationPrivilegeEvaluator privilegeEvaluator() throws Exception {
        FilterSecurityInterceptor securityInterceptor = springSecurityFilterChainBuilder().securityInterceptor();
        return securityInterceptor == null ? null : new DefaultWebInvocationPrivilegeEvaluator(securityInterceptor);
    }

    @Autowired(required = false)
    public void setFilterChainProxySecurityConfigurator(
            SecurityConfigurator<FilterChainProxy, WebSecurityConfiguration>[] webSecurityConfigurers) throws Exception {
        this.hasConfigurators = webSecurityConfigurers != null && webSecurityConfigurers.length > 0;

        Arrays.sort(webSecurityConfigurers,AnnotationAwareOrderComparator.INSTANCE);
        for(SecurityConfigurator<FilterChainProxy, WebSecurityConfiguration> webSecurityConfigurer : webSecurityConfigurers) {
            apply(webSecurityConfigurer);
        }
    }

    SpringSecurityFilterChainBuilder springSecurityFilterChainBuilder() throws Exception {
        return springSecurityFilterChain;
    }

    void setAuthenticationManager(AuthenticationManager authenticationManager) {
        if(authenticationManager != null) {
            this.authenticationManager.setTarget(authenticationManager);
        }
    }

    void setUserDetailsService(UserDetailsService userDetailsService) {
        if(userDetailsService != null) {
            this.userDetailsService.setTarget(userDetailsService);
        }
    }

    private ProxyFactoryBean lazyBean(Class<?> interfaceName) {
        ProxyFactoryBean proxyFactory = new ProxyFactoryBean();
        proxyFactory.setTargetSource(new NullTargetSource(interfaceName));
        proxyFactory.setInterfaces(new Class[] { interfaceName });
        return proxyFactory;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.AbstractSecurityBuilder#doBuild()
     */
    @Override
    protected FilterChainProxy doBuild() throws Exception {
        if(!hasConfigurators) {
            throw new IllegalStateException("At least one non-null instance of WebSecurityConfigurerAdapater must be exposed as a @Bean when using @EnableWebSecurity");
        }
        init();
        configure();
        return springSecurityFilterChain.build();
    }

    private static final class NullTargetSource implements TargetSource {
        private final Class<?> targetClass;

        private NullTargetSource(Class<?> targetClass) {
            this.targetClass = targetClass;
        }

        public Class<?> getTargetClass() {
            return targetClass;
        }

        public boolean isStatic() {
            return true;
        }

        public Object getTarget() throws Exception {
            return null;
        }

        public void releaseTarget(Object target) throws Exception {
        }
    }
}

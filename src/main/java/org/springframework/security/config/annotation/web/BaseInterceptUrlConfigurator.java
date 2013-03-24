/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web;

import java.util.List;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.ConsensusBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * @author Rob Winch
 *
 */
abstract class BaseInterceptUrlConfigurator<T> extends
        BaseRequestMatcherRegistry<T,DefaultSecurityFilterChain,HttpConfiguration> implements
        SecurityConfigurator<DefaultSecurityFilterChain,HttpConfiguration> {
    private Boolean filterSecurityInterceptorOncePerRequest;

    private AccessDecisionManager accessDecisionManager;

    public T accessDecisionManager(
            AccessDecisionManager accessDecisionManager) {
        this.accessDecisionManager = accessDecisionManager;
        return (T) this;
    }

    private AccessDecisionManager accessDecisionManager() {
        if (accessDecisionManager == null) {
            accessDecisionManager = createDefaultAccessDecisionManager();
        }
        return accessDecisionManager;
    }

    public T filterSecurityInterceptorOncePerRequest(
            boolean filterSecurityInterceptorOncePerRequest) {
        this.filterSecurityInterceptorOncePerRequest = filterSecurityInterceptorOncePerRequest;
        return (T) this;
    }

    final AccessDecisionManager createDefaultAccessDecisionManager() {
        return new ConsensusBased(decisionVoters());
    }

    protected void doConfigure(HttpConfiguration http) throws Exception {
        FilterInvocationSecurityMetadataSource metadataSource = createMetadataSource();
        if(metadataSource == null) {
            return;
        }
        FilterSecurityInterceptor securityInterceptor = securityInterceptor(metadataSource , http.authenticationManager());
        if(filterSecurityInterceptorOncePerRequest != null) {
            securityInterceptor.setObserveOncePerRequest(filterSecurityInterceptorOncePerRequest);
        }
        http.addFilter(securityInterceptor);
        http.setSharedObject(FilterSecurityInterceptor.class, securityInterceptor);
    }

    private FilterSecurityInterceptor securityInterceptor(FilterInvocationSecurityMetadataSource metadataSource, AuthenticationManager authenticationManager) throws Exception {
        FilterSecurityInterceptor securityInterceptor = new FilterSecurityInterceptor();
        securityInterceptor.setSecurityMetadataSource(metadataSource);
        securityInterceptor.setAccessDecisionManager(accessDecisionManager());
        securityInterceptor.setAuthenticationManager(authenticationManager);
        securityInterceptor.afterPropertiesSet();
        return securityInterceptor;
    }

    /**
     * @return
     */
    abstract FilterInvocationSecurityMetadataSource createMetadataSource();

    /**
     * @return
     */
    abstract List<AccessDecisionVoter> decisionVoters();
}
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

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class DefaultSecurityFilterConfigurator extends AbstractSecurityFilterConfigurator implements SecurityConfigurator<SecurityFilterChainSecurityBuilder> {
    private BaseFilterInvocationSecurityMetadataSourceBuilder<?> securityMetadataSource;
    private LogoutFilterSecurityBuilder logoutFilterSecurityBuilder = new LogoutFilterSecurityBuilder();
    private boolean permitAll;
    private AnonymousSecurityFilterConfigurator anonymousConfigurator = new AnonymousSecurityFilterConfigurator();
    private boolean disableServletApiProvision;
    private AccessDeniedHandler accessDeniedHandler;
    private AccessDecisionManager accessDecisionManager;
    private Boolean filterSecurityInterceptorOncePerRequest;

    public DefaultSecurityFilterConfigurator(BaseFilterInvocationSecurityMetadataSourceBuilder<?> securityMetadataSource) {
        super();
        this.securityMetadataSource = securityMetadataSource;
    }

    public void init(SecurityFilterChainSecurityBuilder builder) throws Exception {
        builder.setSharedObject(LogoutFilterSecurityBuilder.class, logoutFilterSecurityBuilder);
        if(permitAll) {
            PermitAllSupport.permitAll(builder, logoutFilterSecurityBuilder.getLogoutUrl());
        }
        if(anonymousConfigurator != null) {
            anonymousConfigurator.init(builder);
        }
    }

    public DefaultSecurityFilterConfigurator filterSecurityInterceptorOncePerRequest(boolean filterSecurityInterceptorOncePerRequest) {
        this.filterSecurityInterceptorOncePerRequest = filterSecurityInterceptorOncePerRequest;
        return this;
    }

    public DefaultSecurityFilterConfigurator permitAll() {
        return permitAll(true);
    }

    public DefaultSecurityFilterConfigurator permitAll(boolean permitAll) {
        this.permitAll = permitAll;
        return this;
    }

    public DefaultSecurityFilterConfigurator accessDecisionManager(AccessDecisionManager accessDecisionManager) {
        this.accessDecisionManager = accessDecisionManager;
        return this;
    }

    public DefaultSecurityFilterConfigurator disableServletApiProvision(boolean disableServeltApiProvision) {
        this.disableServletApiProvision = disableServeltApiProvision;
        return this;
    }

    public DefaultSecurityFilterConfigurator withAnonymous(AnonymousSecurityFilterConfigurator anonymousConfigurator) {
        this.anonymousConfigurator = anonymousConfigurator;
        return this;
    }

    public DefaultSecurityFilterConfigurator withLogout(LogoutFilterSecurityBuilder logoutBuilder) {
        this.logoutFilterSecurityBuilder = logoutBuilder;
        return this;
    }

    public DefaultSecurityFilterConfigurator disableAnonymous(boolean disabled) {
        this.anonymousConfigurator = null;
        return this;
    }

    public DefaultSecurityFilterConfigurator accessDeniedPage(String accessDeniedUrl) {
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage(accessDeniedUrl);
        return accessDeniedHandler(accessDeniedHandler);
    }

    public DefaultSecurityFilterConfigurator accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        this.accessDeniedHandler = accessDeniedHandler;
        return this;
    }

    BaseFilterInvocationSecurityMetadataSourceBuilder<?> filterInvocationSecurityMetadataSourceBuilder() {
        return securityMetadataSource;
    }

    public void configure(SecurityFilterChainSecurityBuilder builder) throws Exception {

        SecurityContextPersistenceFilter securityContextFilter = new SecurityContextPersistenceFilter(builder.getSharedObject(SecurityContextRepository.class));
        securityContextFilter.afterPropertiesSet();

        LogoutFilter logoutFilter = logoutFilterSecurityBuilder.build();

        RequestCacheAwareFilter requestCacheFilter = new RequestCacheAwareFilter();

        ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(builder.authenticationEntryPoint());
        if(accessDeniedHandler != null) {
            exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler);
        }

        builder.addFilter(securityContextFilter);
        builder.addFilter(logoutFilter);
        builder.addFilter(requestCacheFilter);

        if(!disableServletApiProvision) {
            SecurityContextHolderAwareRequestFilter securityContextRequestFilter = new SecurityContextHolderAwareRequestFilter();
            securityContextRequestFilter.afterPropertiesSet();
            builder.addFilter(securityContextRequestFilter);
        }

        if(anonymousConfigurator != null) {
            anonymousConfigurator.configure(builder);
        }
        builder.addFilter(exceptionTranslationFilter);
        FilterSecurityInterceptor securityInterceptor = securityInterceptor(builder.authenticationManager());
        if(filterSecurityInterceptorOncePerRequest != null) {
            securityInterceptor.setObserveOncePerRequest(filterSecurityInterceptorOncePerRequest);
        }
        builder.addFilter(securityInterceptor);
        builder.setSharedObject(FilterSecurityInterceptor.class, securityInterceptor);
    }

    private FilterSecurityInterceptor securityInterceptor(AuthenticationManager authenticationManager) throws Exception {
        FilterSecurityInterceptor securityInterceptor = new FilterSecurityInterceptor();
        securityInterceptor.setSecurityMetadataSource(securityMetadataSource.build());
        securityInterceptor.setAccessDecisionManager(accessDecisionManager());
        securityInterceptor.setAuthenticationManager(authenticationManager);
        securityInterceptor.afterPropertiesSet();
        return securityInterceptor;
    }

    private AccessDecisionManager accessDecisionManager() {
        if(accessDecisionManager == null) {
            accessDecisionManager = securityMetadataSource.createDefaultAccessDecisionManager();
        }
        return accessDecisionManager;
    }
}

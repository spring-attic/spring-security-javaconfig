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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.AbstractConfiguredBuilder;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.AnyRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class SecurityFilterChainSecurityBuilder extends AbstractConfiguredBuilder<DefaultSecurityFilterChain,SecurityFilterChainSecurityBuilder> implements SecurityBuilder<DefaultSecurityFilterChain>{

    private AuthenticationManager authenticationManager;

    private List<Filter> filters =  new ArrayList<Filter>();
    private RequestMatcher requestMatcher = new AnyRequestMatcher();
    private FilterComparator comparitor = new FilterComparator();
    private AuthenticationEntryPoint authenticationEntryPoint = new Http403ForbiddenEntryPoint();
    private final Map<Class<Object>,Object> sharedObjects = new HashMap<Class<Object>,Object>();

    public SecurityFilterChainSecurityBuilder(AuthenticationManager authenticationManager) {
        initDefaults(authenticationManager);
    }

    public SecurityFilterChainSecurityBuilder(AuthenticationProvider provider) {
        this(new ProviderManager(Arrays.<AuthenticationProvider>asList(provider)));
    }

    public SecurityFilterChainSecurityBuilder(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        initDefaults(new ProviderManager(Arrays.<AuthenticationProvider>asList(provider)));
    }

    public SecurityFilterChainSecurityBuilder applyDefaultConfigurators() throws Exception {
        exceptionHandling();
        sessionManagement();
        securityContext();
        requestCache();
        anonymous();
        servletApi();
        logout();
        return this;
    }

    protected <C extends SecurityConfigurator<DefaultSecurityFilterChain, SecurityFilterChainSecurityBuilder>> C getConfigurator(
            Class<C> clazz) {
        return super.getConfigurator(clazz);
    }

    public SessionManagementConfigurator sessionManagement() throws Exception {
        return apply(new SessionManagementConfigurator());
    }

    public ExpressionUrlAuthorizationRegistry authorizeUrls() throws Exception {
        return apply(new ExpressionUrlAuthorizationRegistry());
    }

    public RequestCacheConfigurator requestCache() throws Exception {
        return apply(new RequestCacheConfigurator());
    }

    public ExceptionHandlingConfigurator exceptionHandling() throws Exception {
        return apply(new ExceptionHandlingConfigurator());
    }

    public SecurityContextConfigurator securityContext() throws Exception {
        return apply(new SecurityContextConfigurator());
    }

    public ServletApiConfigurator servletApi() throws Exception {
        return apply(new ServletApiConfigurator());
    }

    public LogoutConfigurator logout() throws Exception {
        return apply(new LogoutConfigurator());
    }

    public AnonymousSecurityFilterConfigurator anonymous() throws Exception {
        return apply(new AnonymousSecurityFilterConfigurator());
    }

    public FormLoginSecurityFilterConfigurator formLogin() throws Exception {
        return apply(new FormLoginSecurityFilterConfigurator());
    }

    public ChannelSecurityFilterConfigurator requiresChannel() throws Exception {
        return apply(new ChannelSecurityFilterConfigurator());
    }

    public HttpBasicSecurityFilterConfigurator httpBasic() throws Exception {
        return apply(new HttpBasicSecurityFilterConfigurator());
    }

    public void defaultSharedObject(Class<Object> sharedType, Object object) {
        if(!sharedObjects.containsKey(sharedType)) {
            this.sharedObjects.put(sharedType, object);
        }
    }

    @SuppressWarnings("unchecked")
    public <C> void setSharedObject(Class<C> sharedType, C object) {
        this.sharedObjects.put((Class<Object>) sharedType, object);
    }

    @SuppressWarnings("unchecked")
    public <C> C getSharedObject(Class<C> sharedType) {
        return (C) this.sharedObjects.get(sharedType);
    }

    protected DefaultSecurityFilterChain doBuild() throws Exception {
        init();

        this.authenticationManager = getAuthenticationRegistry().build();

        configure();

        Collections.sort(filters,comparitor);
        return new DefaultSecurityFilterChain(requestMatcher, filters);
    }

    public AuthenticationRegistry getAuthenticationRegistry() {
        return getSharedObject(AuthenticationRegistry.class);
    }

    public SecurityFilterChainSecurityBuilder securityContextRepsitory(SecurityContextRepository securityContextRepository) {
        this.setSharedObject(SecurityContextRepository.class, securityContextRepository);
        return this;
    }

    public SecurityFilterChainSecurityBuilder addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) {
        comparitor.registerAfter(filter.getClass(), afterFilter);
        return addFilter(filter);
    }

    public SecurityFilterChainSecurityBuilder addFilterBefore(Filter filter, Class<? extends Filter> afterFilter) {
        comparitor.registerBefore(filter.getClass(), afterFilter);
        return addFilter(filter);
    }

    public SecurityFilterChainSecurityBuilder addFilter(Filter filter) {
        this.filters.add(filter);
        return this;
    }

    public SecurityFilterChainSecurityBuilder requestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
        return this;
    }

    // FIXME shared object or explicit?
    public AuthenticationManager authenticationManager() {
        return authenticationManager;
    }

    public AuthenticationEntryPoint authenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    public SecurityFilterChainSecurityBuilder authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    private void initDefaults(AuthenticationManager parent) {
        HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
        securityContextRepository.setDisableUrlRewriting(true);
        setSharedObject(SecurityContextRepository.class, securityContextRepository);

        AuthenticationRegistry authenticationRegistry = new AuthenticationRegistry()
                .parentAuthenticationManager(parent);
        setSharedObject(AuthenticationRegistry.class, authenticationRegistry);
    }
}
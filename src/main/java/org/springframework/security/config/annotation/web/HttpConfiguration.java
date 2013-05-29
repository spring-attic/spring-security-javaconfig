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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.AnyRequestMatcher;
import org.springframework.security.web.util.RegexRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class HttpConfiguration extends AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain,HttpConfiguration> implements SecurityBuilder<DefaultSecurityFilterChain> {

    private AuthenticationManager authenticationManager;

    private List<Filter> filters =  new ArrayList<Filter>();
    private RequestMatcher requestMatcher = new AnyRequestMatcher();
    private FilterComparator comparitor = new FilterComparator();
    private AuthenticationEntryPoint authenticationEntryPoint = new Http403ForbiddenEntryPoint();
    private final Map<Class<Object>,Object> sharedObjects = new HashMap<Class<Object>,Object>();

    public HttpConfiguration(AuthenticationManagerBuilder authenticationBuilder) {
        initSharedObjects(authenticationBuilder);
    }

    @Override
    public <C extends SecurityConfigurator<DefaultSecurityFilterChain, HttpConfiguration>> C getConfigurator(
            Class<C> clazz) {
        return super.getConfigurator(clazz);
    }

    public OpenIDLoginConfigurator openidLogin() throws Exception {
        return apply(new OpenIDLoginConfigurator());
    }

    public SessionManagementConfigurator sessionManagement() throws Exception {
        return apply(new SessionManagementConfigurator());
    }

    public PortMapperConfigurator portMapper() throws Exception {
        return apply(new PortMapperConfigurator());
    }

    public JeeConfigurator jee() throws Exception {
        return apply(new JeeConfigurator());
    }

    public X509Configurator x509() throws Exception {
        return apply(new X509Configurator());
    }

    public RememberMeConfigurator rememberMe() throws Exception {
        return apply(new RememberMeConfigurator());
    }

    public ExpressionUrlAuthorizations authorizeUrls() throws Exception {
        return apply(new ExpressionUrlAuthorizations());
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

    public AnonymousConfigurator anonymous() throws Exception {
        return apply(new AnonymousConfigurator());
    }

    public FormLoginConfigurator formLogin() throws Exception {
        return apply(new FormLoginConfigurator());
    }

    public ChannelSecurityFilterConfigurator requiresChannel() throws Exception {
        return apply(new ChannelSecurityFilterConfigurator());
    }

    public HttpBasicConfigurator httpBasic() throws Exception {
        return apply(new HttpBasicConfigurator());
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

    @Override
    protected void beforeConfigure() throws Exception {
        this.authenticationManager = getAuthenticationRegistry().build();
    }

    @Override
    protected DefaultSecurityFilterChain performBuild() throws Exception {
        Collections.sort(filters,comparitor);
        return new DefaultSecurityFilterChain(requestMatcher, filters);
    }

    public HttpConfiguration authenticationProvider(AuthenticationProvider authenticationProvider) {
        getAuthenticationRegistry().add(authenticationProvider);
        return this;
    }

    public HttpConfiguration userDetailsService(UserDetailsService userDetailsService) throws Exception {
        getAuthenticationRegistry().userDetailsService(userDetailsService);
        return this;
    }

    private AuthenticationManagerBuilder getAuthenticationRegistry() {
        return getSharedObject(AuthenticationManagerBuilder.class);
    }

    public HttpConfiguration securityContextRepsitory(SecurityContextRepository securityContextRepository) {
        this.setSharedObject(SecurityContextRepository.class, securityContextRepository);
        return this;
    }

    public HttpConfiguration addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) {
        comparitor.registerAfter(filter.getClass(), afterFilter);
        return addFilter(filter);
    }

    public HttpConfiguration addFilterBefore(Filter filter, Class<? extends Filter> afterFilter) {
        comparitor.registerBefore(filter.getClass(), afterFilter);
        return addFilter(filter);
    }

    public HttpConfiguration addFilter(Filter filter) {
        Class<? extends Filter> filterClass = filter.getClass();
        if(!comparitor.isRegistered(filterClass)) {
            throw new IllegalArgumentException(
                    "The Filter class " + filterClass.getName()
                            + " does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead.");
        }
        this.filters.add(filter);
        return this;
    }

    public RequestMatcherRegistry requestMatchers() {
        return new RequestMatcherRegistry();
    }

    public HttpConfiguration requestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
        return this;
    }

    public HttpConfiguration antMatcher(String pattern) {
        return requestMatcher(new AntPathRequestMatcher(pattern));
    }

    public HttpConfiguration regexMatcher(String pattern) {
        return requestMatcher(new RegexRequestMatcher(pattern, null));
    }

    // FIXME shared object or explicit?
    public AuthenticationManager authenticationManager() {
        return authenticationManager;
    }

    public AuthenticationEntryPoint authenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    public HttpConfiguration authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    public final class RequestMatcherRegistry extends BaseRequestMatcherRegistry<HttpConfiguration,DefaultSecurityFilterChain,HttpConfiguration> {

        @Override
        HttpConfiguration chainRequestMatchers(List<RequestMatcher> requestMatchers) {
            requestMatcher(new OrRequestMatcher(requestMatchers));
            return HttpConfiguration.this;
        }

        private RequestMatcherRegistry(){}
    }

    private void initSharedObjects(AuthenticationManagerBuilder authenticationBuilder) {
        setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
    }

    private static class OrRequestMatcher implements RequestMatcher {
        private final List<RequestMatcher> requestMatchers;

        private OrRequestMatcher(List<RequestMatcher> requestMatchers) {
            this.requestMatchers = requestMatchers;
        }

        @Override
        public boolean matches(HttpServletRequest request) {
            for(RequestMatcher matcher : requestMatchers) {
                if(matcher.matches(request)) {
                    return true;
                }
            }
            return false;
        }
    }
}
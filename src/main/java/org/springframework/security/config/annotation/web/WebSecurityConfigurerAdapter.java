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


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.FilterChainProxy;

/**
 * @author Rob Winch
 *
 */
public abstract class WebSecurityConfigurerAdapter implements WebSecurityConfigurer {

    private AuthenticationBuilder authenticationRegistry = new AuthenticationBuilder();
    private AuthenticationManager authenticationManager;
    private HttpConfiguration springSecurityFilterChain;

    protected abstract AuthenticationManager authenticationManager(AuthenticationBuilder authentication) throws Exception;

    protected void applyDefaults(HttpConfiguration http) throws Exception {
        http.applyDefaultConfigurators();
        authorizeUrls(http.authorizeUrls());
    }

    protected abstract void authorizeUrls(ExpressionUrlAuthorizations interceptUrls);

    private HttpConfiguration springSecurityFilterChain() throws Exception {
        if(springSecurityFilterChain == null) {
            springSecurityFilterChain = new HttpConfiguration(getAuthenticationManager());
        }
        return springSecurityFilterChain;
    }

    public HttpConfiguration httpConfiguration() throws Exception {
        HttpConfiguration springSecurityFilterChain = springSecurityFilterChain();
        springSecurityFilterChain.setSharedObject(UserDetailsService.class, getUserDetailsService());
        applyDefaults(springSecurityFilterChain);
        configure(springSecurityFilterChain);
        return springSecurityFilterChain;
    }

    public AuthenticationManager getAuthenticationManager() throws Exception {
        if(authenticationManager == null) {
            authenticationManager = authenticationManager(authenticationRegistry);
        }
        return authenticationManager;
    }

    public UserDetailsService getUserDetailsService() throws Exception {
        return userDetailsService(authenticationRegistry);
    }

    protected UserDetailsService userDetailsService(AuthenticationBuilder authenticationRegistry) {
        return authenticationRegistry.userDetailsService();
    }

    protected void performConfigure(SpringSecurityFilterChainBuilder securityFilterChains){

    }

    public void init(WebSecurityConfiguration builder) throws Exception {
        SpringSecurityFilterChainBuilder securityFilterChains = builder.springSecurityFilterChainBuilder();
        ignoredRequests(securityFilterChains.ignoring());
        performConfigure(securityFilterChains);
        securityFilterChains
            .securityFilterChains(httpConfiguration());
    }

    public void configure(WebSecurityConfiguration builder) throws Exception {
    }

    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {

    }

    protected abstract void configure(HttpConfiguration http) throws Exception;
}
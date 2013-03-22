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


import java.util.Collections;
import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.RequestMatcher;

/**
 * @author Rob Winch
 *
 */
public abstract class WebSecurityConfigurerAdapater {
    private AuthenticationRegistry authenticationRegistry = new AuthenticationRegistry();
    private AuthenticationManager authenticationManager;

    protected abstract void registerAuthentication(AuthenticationRegistry authenticationRegistry) throws Exception;

    protected void applyDefaults(HttpConfiguration builder) throws Exception {
        builder.applyDefaultConfigurators();
        authorizeUrls(builder.authorizeUrls());
    }

    protected abstract void authorizeUrls(ExpressionUrlAuthorizationRegistry interceptUrls);

    public HttpConfiguration defaultSecurityFilterChainBuilder() throws Exception {
        HttpConfiguration springSecurityFilterChain = new HttpConfiguration(authenticationManager());
        springSecurityFilterChain.setSharedObject(UserDetailsService.class, authenticationRegistry.userDetailsService());
        applyDefaults(springSecurityFilterChain);
        configure(springSecurityFilterChain);
        return springSecurityFilterChain;
    }

    public AuthenticationManager authenticationManager() throws Exception {
        if(authenticationManager == null) {
            authenticationManager = createAuthenticationManager();
        }
        return authenticationManager;
    }

    private AuthenticationManager createAuthenticationManager() throws Exception {
        registerAuthentication(authenticationRegistry);
        return authenticationRegistry.build();
    }

    public UserDetailsService userDetailsService() {
        return authenticationRegistry.userDetailsService();
    }

    final void performConfigure(SpringSecurityFilterChainBuilder securityFilterChains){
        securityFilterChains
            .ignoring(ignoredRequests());
        configure(securityFilterChains);
    }

    protected void configure(SpringSecurityFilterChainBuilder securityFilterChains){

    }

    public List<RequestMatcher> ignoredRequests() {
        return Collections.emptyList();
    }

    protected abstract void configure(HttpConfiguration springSecurityFilterChain) throws Exception;
}
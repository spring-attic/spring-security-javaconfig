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
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author Rob Winch
 *
 */
public abstract class WebSecurityConfigurerAdapater {
    private AuthenticationRegistry authenticationRegistry = new AuthenticationRegistry();
    private AuthenticationManager authenticationManager;

    protected abstract AuthenticationManager authenticationManager(AuthenticationRegistry authentication) throws Exception;

    protected void applyDefaults(HttpConfiguration http) throws Exception {
        http.applyDefaultConfigurators();
        authorizeUrls(http.authorizeUrls());
    }

    protected abstract void authorizeUrls(ExpressionUrlAuthorizations interceptUrls);

    public HttpConfiguration httpConfiguration() throws Exception {
        HttpConfiguration springSecurityFilterChain = new HttpConfiguration(authenticationManager());
        springSecurityFilterChain.setSharedObject(UserDetailsService.class, userDetailsService());
        applyDefaults(springSecurityFilterChain);
        configure(springSecurityFilterChain);
        return springSecurityFilterChain;
    }

    public final AuthenticationManager authenticationManager() throws Exception {
        if(authenticationManager == null) {
            authenticationManager = authenticationManager(authenticationRegistry);
        }
        return authenticationManager;
    }

    public final UserDetailsService userDetailsService() throws Exception {
        return userDetailsService(authenticationRegistry);
    }

    protected UserDetailsService userDetailsService(AuthenticationRegistry authenticationRegistry) {
        return authenticationRegistry.userDetailsService();
    }

    final void performConfigure(SpringSecurityFilterChainBuilder securityFilterChains){
        ignoredRequests(securityFilterChains.ignoring());
        configure(securityFilterChains);
    }

    protected void configure(SpringSecurityFilterChainBuilder securityFilterChains){

    }

    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {

    }

    protected abstract void configure(HttpConfiguration http) throws Exception;
}
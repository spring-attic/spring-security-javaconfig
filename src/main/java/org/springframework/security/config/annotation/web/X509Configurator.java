/*
 * Copyright 2002-2012 the original author or authors.
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

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.AbstractSecurityConfigurator;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class X509Configurator extends AbstractSecurityConfigurator<DefaultSecurityFilterChain, HttpConfigurator> {
    private X509AuthenticationFilter x509AuthenticationFilter;
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService;
    private String subjectPrincipalRegex;
    private AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> authenticationDetailsSource;

    public X509Configurator x509AuthenticationFilter(
            X509AuthenticationFilter x509AuthenticationFilter) {
        this.x509AuthenticationFilter = x509AuthenticationFilter;
        return this;
    }

    public X509Configurator authenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        return this;
    }

    public X509Configurator userDetailsService(
            UserDetailsService userDetailsService) {
        UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService = new UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>();
        authenticationUserDetailsService.setUserDetailsService(userDetailsService);
        return authenticationUserDetailsService(authenticationUserDetailsService);
    }

    public X509Configurator authenticationUserDetailsService(
            AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService) {
        this.authenticationUserDetailsService = authenticationUserDetailsService;
        return this;
    }

    public X509Configurator subjectPrincipalRegex(String subjectPrincipalRegex) {
        this.subjectPrincipalRegex = subjectPrincipalRegex;
        return this;
    }

    @Override
    protected void doInit(HttpConfigurator http) throws Exception {
        PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(getAuthenticationUserDetailsService(http));

        http
            .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
                .authenticationProvider(authenticationProvider);
    }

    @Override
    protected void doConfigure(HttpConfigurator http) throws Exception {
        X509AuthenticationFilter filter = getFilter(http.authenticationManager());
        http.addFilter(filter);
    }

    private X509AuthenticationFilter getFilter(
            AuthenticationManager authenticationManager) {
        if (x509AuthenticationFilter == null) {
            x509AuthenticationFilter = new X509AuthenticationFilter();
            x509AuthenticationFilter.setAuthenticationManager(authenticationManager);
            if(subjectPrincipalRegex != null) {
                SubjectDnX509PrincipalExtractor principalExtractor = new SubjectDnX509PrincipalExtractor();
                principalExtractor.setSubjectDnRegex(subjectPrincipalRegex);
                x509AuthenticationFilter.setPrincipalExtractor(principalExtractor);
            }
            if(authenticationDetailsSource != null) {
                x509AuthenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
            }
            x509AuthenticationFilter.afterPropertiesSet();
        }

        return x509AuthenticationFilter;
    }

    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> getAuthenticationUserDetailsService(
            HttpConfigurator http) {
        if(authenticationUserDetailsService == null) {
            userDetailsService(http.getSharedObject(UserDetailsService.class));
        }
        return authenticationUserDetailsService;
    }

}
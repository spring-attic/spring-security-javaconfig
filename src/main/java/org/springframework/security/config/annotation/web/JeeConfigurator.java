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

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.AbstractSecurityConfigurator;
import org.springframework.security.core.authority.mapping.SimpleMappableAttributesRetriever;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.j2ee.J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class JeeConfigurator extends AbstractSecurityConfigurator<DefaultSecurityFilterChain, HttpConfigurator> {
    private J2eePreAuthenticatedProcessingFilter j2eePreAuthenticatedProcessingFilter;
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> userDetailsService;
    private Set<String> mappableRoles = new HashSet<String>();

    public JeeConfigurator j2eePreAuthenticatedProcessingFilter(
            J2eePreAuthenticatedProcessingFilter j2eePreAuthenticatedProcessingFilter) {
        this.j2eePreAuthenticatedProcessingFilter = j2eePreAuthenticatedProcessingFilter;
        return this;
    }

    public JeeConfigurator userDetailsService(
            AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> userDetailsService) {
        this.userDetailsService = userDetailsService;
        return this;
    }

    public JeeConfigurator mappableRoles(String... mappableRoles) {
        for(String role : mappableRoles) {
            this.mappableRoles.add(role);
        }
        return this;
    }

    public JeeConfigurator mappableRoles(Set<String> mappableRoles) {
        this.mappableRoles = mappableRoles;
        return this;
    }

    @Override
    protected void doInit(HttpConfigurator http) throws Exception {
        PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(getUserDetailsService(http));

        http
            .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
            .authenticationProvider(authenticationProvider);
    }

    @Override
    protected void doConfigure(HttpConfigurator http) throws Exception {
        J2eePreAuthenticatedProcessingFilter filter = getFilter(http
                .authenticationManager());
        http.addFilter(filter);
    }

    private J2eePreAuthenticatedProcessingFilter getFilter(
            AuthenticationManager authenticationManager) {
        if (j2eePreAuthenticatedProcessingFilter == null) {
            j2eePreAuthenticatedProcessingFilter = new J2eePreAuthenticatedProcessingFilter();
            j2eePreAuthenticatedProcessingFilter
                    .setAuthenticationManager(authenticationManager);
            j2eePreAuthenticatedProcessingFilter
                    .setAuthenticationDetailsSource(detailsSource());
        }

        return j2eePreAuthenticatedProcessingFilter;
    }

    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> getUserDetailsService(
            HttpConfigurator http) {
        return userDetailsService == null ? new PreAuthenticatedGrantedAuthoritiesUserDetailsService()
                : userDetailsService;
    }

    private J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource detailsSource() {
        J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource detailsSource = new J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource();
        SimpleMappableAttributesRetriever rolesRetriever = new SimpleMappableAttributesRetriever();
        rolesRetriever.setMappableAttributes(mappableRoles);
        detailsSource.setMappableRolesRetriever(rolesRetriever);
        return detailsSource;
    }
}
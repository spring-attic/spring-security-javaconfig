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

import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.core.authority.mapping.SimpleMappableAttributesRetriever;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.j2ee.J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;

/**
 * Adds support for J2EE pre authentication.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>
 * {@link J2eePreAuthenticatedProcessingFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * <ul>
 * <li>
 * {@link HttpConfiguration#authenticationEntryPoint(org.springframework.security.web.AuthenticationEntryPoint)}
 * is populated with an {@link Http403ForbiddenEntryPoint}</li>
 * <li>A {@link PreAuthenticatedAuthenticationProvider} is populated into
 * {@link HttpConfiguration#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)}
 * </li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link HttpConfiguration#authenticationManager()}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class JeeConfigurator extends SecurityConfiguratorAdapter<DefaultSecurityFilterChain, HttpConfiguration> {
    private J2eePreAuthenticatedProcessingFilter j2eePreAuthenticatedProcessingFilter;
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService;
    private Set<String> mappableRoles = new HashSet<String>();

    /**
     * Creates a new instance
     * @see HttpConfiguration#jee()
     */
    JeeConfigurator() {
    }

    /**
     * Specifies roles to use map from the {@link HttpServletRequest} to the
     * {@link UserDetails}. If {@link HttpServletRequest#isUserInRole(String)}
     * returns true, the role is added to the {@link UserDetails}.
     *
     * <p>There are no default roles that are mapped.</p>
     *
     * @param mappableRoles
     *            the roles to attempt to map to the {@link UserDetails} (i.e.
     *            "ROLE_USER", "ROLE_ADMIN", etc).
     * @return the {@link JeeConfigurator} for further customizations
     * @see SimpleMappableAttributesRetriever
     */
    public JeeConfigurator mappableRoles(String... mappableRoles) {
        for(String role : mappableRoles) {
            this.mappableRoles.add(role);
        }
        return this;
    }

    /**
     * Specifies roles to use map from the {@link HttpServletRequest} to the
     * {@link UserDetails}. If {@link HttpServletRequest#isUserInRole(String)}
     * returns true, the role is added to the {@link UserDetails}.
     *
     * <p>There are no default roles that are mapped.</p>
     *
     * @param mappableRoles the roles to attempt to map to the {@link UserDetails}.
     * @return the {@link JeeConfigurator} for further customizations
     * @see SimpleMappableAttributesRetriever
     */
    public JeeConfigurator mappableRoles(Set<String> mappableRoles) {
        this.mappableRoles = mappableRoles;
        return this;
    }

    /**
     * Specifies the {@link AuthenticationUserDetailsService} that is used with
     * the {@link PreAuthenticatedAuthenticationProvider}. The default is a
     * {@link PreAuthenticatedGrantedAuthoritiesUserDetailsService}.
     *
     * @param authenticatedUserDetailsService the {@link AuthenticationUserDetailsService} to use.
     * @return the {@link JeeConfigurator} for further configuration
     */
    public JeeConfigurator authenticatedUserDetailsService(
            AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticatedUserDetailsService) {
        this.authenticationUserDetailsService = authenticatedUserDetailsService;
        return this;
    }

    /**
     * Allows specifying the {@link J2eePreAuthenticatedProcessingFilter} to
     * use. If {@link J2eePreAuthenticatedProcessingFilter} is provided, all of its attributes must also be
     * configured manually (i.e. all attributes populated in the {@link JeeConfigurator} are not used).
     *
     * @param j2eePreAuthenticatedProcessingFilter the {@link J2eePreAuthenticatedProcessingFilter} to use.
     * @return the {@link JeeConfigurator} for further configuration
     */
    public JeeConfigurator j2eePreAuthenticatedProcessingFilter(
            J2eePreAuthenticatedProcessingFilter j2eePreAuthenticatedProcessingFilter) {
        this.j2eePreAuthenticatedProcessingFilter = j2eePreAuthenticatedProcessingFilter;
        return this;
    }

    /**
     * Populates a {@link PreAuthenticatedAuthenticationProvider} into
     * {@link HttpConfiguration#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)}
     * and a {@link Http403ForbiddenEntryPoint} into
     * {@link HttpConfiguration#authenticationEntryPoint(org.springframework.security.web.AuthenticationEntryPoint)}
     *
     * @see org.springframework.security.config.annotation.SecurityConfiguratorAdapter#init(org.springframework.security.config.annotation.SecurityBuilder)
     */
    @Override
    public void init(HttpConfiguration http) throws Exception {
        PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(getUserDetailsService());

        http
            .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
            .authenticationProvider(authenticationProvider);
    }

    @Override
    public void configure(HttpConfiguration http) throws Exception {
        J2eePreAuthenticatedProcessingFilter filter = getFilter(http
                .authenticationManager());
        http.addFilter(filter);
    }

    /**
     * Gets the {@link J2eePreAuthenticatedProcessingFilter} or creates a default instance using the properties provided.
     * @param authenticationManager the {@link AuthenticationManager} to use.
     * @return the {@link J2eePreAuthenticatedProcessingFilter} to use.
     */
    private J2eePreAuthenticatedProcessingFilter getFilter(
            AuthenticationManager authenticationManager) {
        if (j2eePreAuthenticatedProcessingFilter == null) {
            j2eePreAuthenticatedProcessingFilter = new J2eePreAuthenticatedProcessingFilter();
            j2eePreAuthenticatedProcessingFilter
                    .setAuthenticationManager(authenticationManager);
            j2eePreAuthenticatedProcessingFilter
                    .setAuthenticationDetailsSource(createWebAuthenticationDetailsSource());
            j2eePreAuthenticatedProcessingFilter.afterPropertiesSet();
        }

        return j2eePreAuthenticatedProcessingFilter;
    }

    /**
     * Gets the {@link AuthenticationUserDetailsService} that was specified or
     * defaults to {@link PreAuthenticatedGrantedAuthoritiesUserDetailsService}.
     *
     * @return the {@link AuthenticationUserDetailsService} to use
     */
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> getUserDetailsService() {
        return authenticationUserDetailsService == null ? new PreAuthenticatedGrantedAuthoritiesUserDetailsService()
                : authenticationUserDetailsService;
    }

    /**
     * Creates the
     * {@link J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource} to set on
     * the {@link J2eePreAuthenticatedProcessingFilter}. It is populated with a
     * {@link SimpleMappableAttributesRetriever}.
     *
     * @return the
     *         {@link J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource}
     *         to use.
     */
    private J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource createWebAuthenticationDetailsSource() {
        J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource detailsSource = new J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource();
        SimpleMappableAttributesRetriever rolesRetriever = new SimpleMappableAttributesRetriever();
        rolesRetriever.setMappableAttributes(mappableRoles);
        detailsSource.setMappableRolesRetriever(rolesRetriever);
        return detailsSource;
    }
}
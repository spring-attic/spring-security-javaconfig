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

import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Allows persisting and restoring of the {@link SecurityContext} found on the
 * {@link SecurityContextHolder} for each request by configuring the
 * {@link SecurityContextPersistenceFilter}. All properties have reasonable
 * defaults, so no additional configuration is required other than applying this
 * {@link org.springframework.security.config.annotation.SecurityConfigurator}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link SecurityContextPersistenceFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>If {@link SessionManagementConfigurator}, is provided and set to always,
 * then the
 * {@link SecurityContextPersistenceFilter#setForceEagerSessionCreation(boolean)}
 * will be set to true.</li>
 * <li>{@link SecurityContextRepository} must be set and is used on
 * {@link SecurityContextPersistenceFilter}. This is typically configured using
 * {@link HttpConfiguration#securityContextRepsitory(SecurityContextRepository)}.</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class SecurityContextConfigurator extends
        SecurityConfiguratorAdapter<DefaultSecurityFilterChain, HttpConfiguration> {

    /**
     * Creates a new instance
     * @see HttpConfiguration#securityContext()
     */
    SecurityContextConfigurator() {
    }

    @Override
    public void configure(HttpConfiguration http) throws Exception {

        SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
        SecurityContextPersistenceFilter securityContextFilter = new SecurityContextPersistenceFilter(
                securityContextRepository);
        SessionManagementConfigurator sessionManagement = http
                .getConfigurator(SessionManagementConfigurator.class);
        SessionCreationPolicy sessionCreationPolicy = sessionManagement == null ? null
                : sessionManagement.getSessionCreationPolicy();
        if (SessionCreationPolicy.always == sessionCreationPolicy) {
            securityContextFilter.setForceEagerSessionCreation(true);
        }
        securityContextFilter.afterPropertiesSet();
        http.addFilter(securityContextFilter);
    }
}
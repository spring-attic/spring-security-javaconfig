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

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

/**
 * Implements select methods from the {@link HttpServletRequest} using the {@link SecurityContext} from the {@link SecurityContextHolder}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link SecurityContextHolderAwareRequestFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * No shared Objects are used.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class ServletApiConfigurator extends SecurityConfiguratorAdapter<DefaultSecurityFilterChain,HttpConfiguration> {
    private SecurityContextHolderAwareRequestFilter securityContextRequestFilter = new SecurityContextHolderAwareRequestFilter();

    /**
     * Creates a new instance
     * @see HttpConfiguration#servletApi()
     */
    ServletApiConfigurator() {
    }

    public ServletApiConfigurator rolePrefix(String rolePrefix) {
        securityContextRequestFilter.setRolePrefix(rolePrefix);
        return this;
    }

    public HttpConfiguration disable() {
        return and().removeConfigurator(getClass()).and();
    }

    @Override
    public void configure(HttpConfiguration builder)
            throws Exception {
        securityContextRequestFilter.afterPropertiesSet();
        builder.addFilter(securityContextRequestFilter);
    }
}
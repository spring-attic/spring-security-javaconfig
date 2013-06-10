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

import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 * Adds exception handling for Spring Security related exceptions to an application. All properties have reasonable
 * defaults, so no additional configuration is required other than applying this
 * {@link org.springframework.security.config.annotation.SecurityConfigurator}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 *     <li>{@link ExceptionTranslationFilter}</li>
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
 *     <li>{@link HttpConfiguration#authenticationEntryPoint()} is used to process requests that require
 *     authentication</li>
 *     <li>If no explicit {@link RequestCache}, is provided a {@link RequestCache} shared object is used to replay
 *     the request after authentication is successful</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class ExceptionHandlingConfigurator extends BaseHttpConfigurator {

    private AccessDeniedHandler accessDeniedHandler;
    private RequestCache requestCache;

    /**
     * Creates a new instance
     * @see HttpConfiguration#exceptionHandling()
     */
    ExceptionHandlingConfigurator() {
    }

    /**
     * Shortcut to specify the {@link AccessDeniedHandler} to be used is a specific error page
     *
     * @param accessDeniedUrl the URL to the access denied page (i.e. /errors/401)
     * @return the {@link ExceptionHandlingConfigurator} for further customization
     * @see AccessDeniedHandlerImpl
     * @see {@link #accessDeniedHandler(org.springframework.security.web.access.AccessDeniedHandler)}
     */
    public ExceptionHandlingConfigurator accessDeniedPage(String accessDeniedUrl) {
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage(accessDeniedUrl);
        return accessDeniedHandler(accessDeniedHandler);
    }

    /**
     * Specifies the {@link AccessDeniedHandler} to be used
     *
     * @param accessDeniedHandler the {@link AccessDeniedHandler} to be used
     * @return the {@link ExceptionHandlingConfigurator} for further customization
     */
    public ExceptionHandlingConfigurator accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        this.accessDeniedHandler = accessDeniedHandler;
        return this;
    }

    /**
     * Allows explicit configuration of the {@link RequestCache} to be used. Defaults to try finding a
     * {@link RequestCache} as a shared object. Then falls back to a {@link HttpSessionRequestCache}.
     *
     * @param requestCache the explicit {@link RequestCache} to use
     * @return the {@link ExceptionHandlingConfigurator} for further customization
     */
    public ExceptionHandlingConfigurator requestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
        return this;
    }

    @Override
    public void configure(HttpConfiguration http) throws Exception {
        ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(http.authenticationEntryPoint(), getRequestCache(http));
        if(accessDeniedHandler != null) {
            exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler);
        }
        exceptionTranslationFilter = registerLifecycle(exceptionTranslationFilter);
        http.addFilter(exceptionTranslationFilter);
    }

    /**
     * Gets the {@link RequestCache} to use. If one is defined using
     * {@link #requestCache(org.springframework.security.web.savedrequest.RequestCache)}, then it is used. Otherwise, an
     * attempt to find a {@link RequestCache} shared object is made. If that fails, an {@link HttpSessionRequestCache}
     * is used
     *
     * @param http the {@link HttpConfiguration} to attempt to fined the shared object
     * @return the {@link RequestCache} to use
     */
    private RequestCache getRequestCache(HttpConfiguration http) {
        if(this.requestCache != null) {
            return this.requestCache;
        }
        RequestCache result = http.getSharedObject(RequestCache.class);
        if(result != null) {
            return result;
        }
        return new HttpSessionRequestCache();
    }
}

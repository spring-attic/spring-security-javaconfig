/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.config.annotation.web;

import org.springframework.security.config.annotation.AbstractConfigurator;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class ExceptionHandlingConfigurator extends AbstractConfigurator<DefaultSecurityFilterChain,HttpConfigurator> {

    private AccessDeniedHandler accessDeniedHandler;
    private RequestCache requestCache;

    public ExceptionHandlingConfigurator accessDeniedPage(String accessDeniedUrl) {
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage(accessDeniedUrl);
        return accessDeniedHandler(accessDeniedHandler);
    }

    public ExceptionHandlingConfigurator accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        this.accessDeniedHandler = accessDeniedHandler;
        return this;
    }

    public ExceptionHandlingConfigurator requestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
        return this;
    }

    @Override
    public void configure(HttpConfigurator http) throws Exception {
        ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(http.authenticationEntryPoint(), getRequestCache(http));
        if(accessDeniedHandler != null) {
            exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler);
        }
        http.addFilter(exceptionTranslationFilter);
    }

    private RequestCache getRequestCache(HttpConfigurator http) {
        if(this.requestCache != null) {
            return this.requestCache;
        }
        RequestCache result = http.getSharedObject(RequestCache.class);
        if(result != null) {
            return result;
        }
        return  new HttpSessionRequestCache();
    }
}

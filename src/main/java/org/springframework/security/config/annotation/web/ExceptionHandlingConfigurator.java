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

import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class ExceptionHandlingConfigurator extends AbstractSecurityFilterConfigurator implements SecurityConfigurator<SecurityFilterChainSecurityBuilder> {

    private AccessDeniedHandler accessDeniedHandler;

    public ExceptionHandlingConfigurator accessDeniedPage(String accessDeniedUrl) {
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage(accessDeniedUrl);
        return accessDeniedHandler(accessDeniedHandler);
    }

    public ExceptionHandlingConfigurator accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        this.accessDeniedHandler = accessDeniedHandler;
        return this;
    }

    void doConfigure(SecurityFilterChainSecurityBuilder builder) throws Exception {
        ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(builder.authenticationEntryPoint());
        if(accessDeniedHandler != null) {
            exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler);
        }
        builder.addFilter(exceptionTranslationFilter);
    }
}

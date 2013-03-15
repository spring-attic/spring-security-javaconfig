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

import org.springframework.security.config.annotation.AbstractSecurityConfigurator;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;

/**
 * @author Rob Winch
 *
 */
public class SessionManagementConfigurator extends AbstractSecurityConfigurator<DefaultSecurityFilterChain,SecurityFilterChainSecurityBuilder> {
    private SessionManagementFilter sessionManagementFilter;
    private SessionAuthenticationStrategy sessionAuthenticationStrategy = new SessionFixationProtectionStrategy();
    private SessionRegistry sessionRegistry = new SessionRegistryImpl();
    private Integer maximumSessions;
    private String expiredUrl;
    private boolean exceptionIfMaximumExceeded;

    public SessionManagementConfigurator sessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
        this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
        return this;
    }

    public SessionManagementConfigurator maximumSessions(int maximumSessions) {
        this.maximumSessions = maximumSessions;
        this.sessionAuthenticationStrategy = null;
        return this;
    }

    public SessionManagementConfigurator expiredUrl(String expiredUrl) {
        this.expiredUrl = expiredUrl;
        return this;
    }

    public SessionManagementConfigurator exceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
        this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
        return this;
    }

    protected void doInit(SecurityFilterChainSecurityBuilder builder)
            throws Exception {
        builder.setSharedObject(SessionAuthenticationStrategy.class, getSessionAuthenticationStrategy());
    }

    protected void doConfigure(SecurityFilterChainSecurityBuilder builder)
            throws Exception {
        sessionManagementFilter = new SessionManagementFilter(builder.getSharedObject(SecurityContextRepository.class), getSessionAuthenticationStrategy());
        builder.addFilter(sessionManagementFilter);
        if(isConcurrentSessionControlEnabled()) {
            ConcurrentSessionFilter concurrentSessionFilter = new ConcurrentSessionFilter(sessionRegistry, expiredUrl);
            builder.addFilter(concurrentSessionFilter);
        }
    }

    private SessionAuthenticationStrategy getSessionAuthenticationStrategy() {
        if(sessionAuthenticationStrategy != null) {
            return sessionAuthenticationStrategy;
        }
        if(isConcurrentSessionControlEnabled()) {
            ConcurrentSessionControlStrategy concurrentSessionControlStrategy = new ConcurrentSessionControlStrategy(sessionRegistry);
            concurrentSessionControlStrategy.setMaximumSessions(maximumSessions);
            concurrentSessionControlStrategy.setExceptionIfMaximumExceeded(exceptionIfMaximumExceeded);
            sessionAuthenticationStrategy = concurrentSessionControlStrategy;
        }
        return sessionAuthenticationStrategy;
    }

    private boolean isConcurrentSessionControlEnabled() {
        return maximumSessions != null;
    }
}

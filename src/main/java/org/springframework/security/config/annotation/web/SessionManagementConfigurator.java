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

import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;

/**
 * Allows configuring session management.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link SessionManagementFilter}</li>
 * <li>{@link ConcurrentSessionFilter} if there are restrictions on how many concurrent sessions a user can have</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are created:
 *
 * <ul>
 * <li>{@link RequestCache}</li>
 * <li>{@link SecurityContextRepository}</li>
 * <li>{@link SessionManagementConfigurator}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * <ul>
 * <li>{@link SecurityContextRepository}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 * @see SessionManagementFilter
 * @see ConcurrentSessionFilter
 */
public final class SessionManagementConfigurator extends BaseHttpConfigurator {
    private SessionManagementFilter sessionManagementFilter;
    private SessionAuthenticationStrategy sessionAuthenticationStrategy = new SessionFixationProtectionStrategy();
    private SessionRegistry sessionRegistry = new SessionRegistryImpl();
    private Integer maximumSessions;
    private String expiredUrl;
    private boolean exceptionIfMaximumExceeded;
    private SessionCreationPolicy sessionPolicy = SessionCreationPolicy.ifRequired;
    private boolean enableSessionUrlRewriting;

    /**
     * Creates a new instance
     * @see HttpConfiguration#sessionManagement()
     */
    SessionManagementConfigurator() {
    }

    /**
     * If set to true, allows HTTP sessions to be rewritten in the URLs when
     * using {@link HttpServletResponse#encodeRedirectURL(String)} or
     * {@link HttpServletResponse#encodeURL(String)}, otherwise disallows HTTP
     * sessions to be included in the URL. This prevents leaking information to
     * external domains.
     *
     * @param enableSessionUrlRewriting true if should allow the JSESSIONID to be rewritten into the URLs, else false (default)
     * @return the {@link SessionManagementConfigurator} for further customization
     * @see HttpSessionSecurityContextRepository#setDisableUrlRewriting(boolean)
     */
    public SessionManagementConfigurator enableSessionUrlRewriting(boolean enableSessionUrlRewriting) {
        this.enableSessionUrlRewriting = enableSessionUrlRewriting;
        return this;
    }

    /**
     * Allows specifying the {@link SessionCreationPolicy}
     * @param sessionCreationPolicy the {@link SessionCreationPolicy} to use. Cannot be null.
     * @return the {@link SessionManagementConfigurator} for further customizations
     * @see SessionCreationPolicy
     * @throws IllegalArgumentException if {@link SessionCreationPolicy} is null.
     */
    public SessionManagementConfigurator sessionCreationPolicy(SessionCreationPolicy sessionCreationPolicy) {
        Assert.notNull(sessionCreationPolicy, "sessionCreationPolicy cannot be null");
        this.sessionPolicy = sessionCreationPolicy;
        return this;
    }

    /**
     * Allows explicitly specifying the {@link SessionAuthenticationStrategy}.
     * The default is to use {@link SessionFixationProtectionStrategy}. If
     * restricting the maximum number of sessions is configured,
     * {@link ConcurrentSessionControlStrategy} will be used.
     *
     * @param sessionAuthenticationStrategy
     * @return the {@link SessionManagementConfigurator} for further customizations
     */
    public SessionManagementConfigurator sessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
        this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
        return this;
    }

    /**
     * Controls the maximum number of sessions for a user. The default is to allow any number of users.
     * @param maximumSessions the maximum number of sessions for a user
     * @return the {@link SessionManagementConfigurator} for further customizations
     */
    public SessionManagementConfigurator maximumSessions(int maximumSessions) {
        this.maximumSessions = maximumSessions;
        this.sessionAuthenticationStrategy = null;
        return this;
    }

    /**
     * The URL to redirect to if a user tries to access a resource and their
     * session has been expired due to too many sessions for the current user.
     * The default is to write a simple error message to the response.
     *
     * @param expiredUrl the URL to redirect to
     * @return the {@link SessionManagementConfigurator} for further customizations
     */
    public SessionManagementConfigurator expiredUrl(String expiredUrl) {
        this.expiredUrl = expiredUrl;
        return this;
    }

    /**
     * If true, prevents a user from authenticating when the
     * {@link #maximumSessions(int)} has been reached. Otherwise (default), the user who
     * authenticates is allowed access and an existing user's session is
     * expired. The user's who's session is forcibly expired is sent to
     * {@link #expiredUrl(String)}. The advantage of this approach is if a user
     * accidentally does not log out, there is no need for an administrator to
     * intervene or wait till their session expires.
     *
     * @param exceptionIfMaximumExceeded true to have an error at time of authentication, else false (default)
     * @return the {@link SessionManagementConfigurator} for further customizations
     */
    public SessionManagementConfigurator exceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
        this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
        return this;
    }

    @Override
    public void init(HttpConfiguration builder)
            throws Exception {
        SecurityContextRepository securityContextRepository = builder.getSharedObject(SecurityContextRepository.class);
        if(securityContextRepository == null) {
            if(isStateless()) {
                builder.setSharedObject(SecurityContextRepository.class, new NullSecurityContextRepository());
                builder.setSharedObject(RequestCache.class, new NullRequestCache());
            } else {
                HttpSessionSecurityContextRepository httpSecurityRepository = new HttpSessionSecurityContextRepository();
                httpSecurityRepository.setDisableUrlRewriting(!enableSessionUrlRewriting);
                httpSecurityRepository.setAllowSessionCreation(isAllowSessionCreation());
                builder.setSharedObject(SecurityContextRepository.class, httpSecurityRepository);
            }
        }
        builder.setSharedObject(SessionAuthenticationStrategy.class, getSessionAuthenticationStrategy());
    }

    @Override
    public void configure(HttpConfiguration http)
            throws Exception {
        SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
        sessionManagementFilter = new SessionManagementFilter(securityContextRepository, getSessionAuthenticationStrategy());
        sessionManagementFilter = registerLifecycle(sessionManagementFilter);

        http.addFilter(sessionManagementFilter);
        if(isConcurrentSessionControlEnabled()) {
            ConcurrentSessionFilter concurrentSessionFilter = new ConcurrentSessionFilter(sessionRegistry, expiredUrl);
            concurrentSessionFilter = registerLifecycle(concurrentSessionFilter);
            http.addFilter(concurrentSessionFilter);
        }
    }

    /**
     * Gets the {@link SessionCreationPolicy}. Can not be null.
     * @return the {@link SessionCreationPolicy}
     */
    SessionCreationPolicy getSessionCreationPolicy() {
        return sessionPolicy;
    }

    /**
     * Returns true if the {@link SessionCreationPolicy} allows session creation, else false
     * @return true if the {@link SessionCreationPolicy} allows session creation
     */
    private boolean isAllowSessionCreation() {
        return SessionCreationPolicy.always == sessionPolicy || SessionCreationPolicy.ifRequired == sessionPolicy;
    }

    /**
     * Returns true if the {@link SessionCreationPolicy} is stateless
     * @return
     */
    private boolean isStateless() {
        return SessionCreationPolicy.stateless == sessionPolicy;
    }

    /**
     * Gets the customized {@link SessionAuthenticationStrategy} if
     * {@link #sessionAuthenticationStrategy(SessionAuthenticationStrategy)} was
     * specified. Otherwise creates a default
     * {@link SessionAuthenticationStrategy}.
     *
     * @return the {@link SessionAuthenticationStrategy} to use
     */
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

    /**
     * Returns true if the number of concurrent sessions per user should be restricted.
     * @return
     */
    private boolean isConcurrentSessionControlEnabled() {
        return maximumSessions != null;
    }
}
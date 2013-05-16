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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.AbstractConfigurator;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class FormLoginConfigurator extends AbstractConfigurator<DefaultSecurityFilterChain,HttpConfigurator> {
    private UsernamePasswordAuthenticationFilter usernamePasswordFilter = new UsernamePasswordAuthenticationFilter() {
        @Override
        protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
            return "POST".equals(request.getMethod()) && super.requiresAuthentication(request, response);
        }
    };

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;
    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationFailureHandler failureHandler;
    private boolean permitAll;
    private String loginPage;
    private String loginProcessingUrl;
    private String failureUrl;

    public FormLoginConfigurator() {
        loginUrl("/login");
        failureUrl("/login?error");
        usernameParameter("username");
        passwordParameter("password");
    }

    @Override
    protected void doInit(HttpConfigurator http) throws Exception {
        if(permitAll) {
            PermitAllSupport.permitAll(http, loginPage, loginProcessingUrl, failureUrl);
        }
        http.authenticationEntryPoint(authenticationEntryPoint);
    }

    @Override
    protected void doConfigure(HttpConfigurator http) throws Exception {
        usernamePasswordFilter.setAuthenticationManager(http.authenticationManager());
        usernamePasswordFilter.setAuthenticationSuccessHandler(successHandler);
        usernamePasswordFilter.setAuthenticationFailureHandler(failureHandler);
        if(authenticationDetailsSource != null) {
            usernamePasswordFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        }
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http.getSharedObject(SessionAuthenticationStrategy.class);
        if(sessionAuthenticationStrategy != null) {
            usernamePasswordFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if(rememberMeServices != null) {
            usernamePasswordFilter.setRememberMeServices(rememberMeServices);
        }
        usernamePasswordFilter.afterPropertiesSet();
        http.addFilter(usernamePasswordFilter);
    }

    public FormLoginConfigurator authenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        return this;
    }

    public FormLoginConfigurator defaultSuccessUrl(String defaultSuccessUrl) {
        return defaultSuccessUrl(defaultSuccessUrl, false);
    }

    public FormLoginConfigurator defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl(defaultSuccessUrl);
        handler.setAlwaysUseDefaultTargetUrl(alwaysUse);
        return successHandler(handler);
    }

    public FormLoginConfigurator successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    /**
     * Specifies the URL used to log in. If the request is an HTTP POST, the
     * {@link UsernamePasswordAuthenticationFilter} will attempt to authenicate
     * the request. Otherwise, the user will be sent to the login form.
     *
     * @param loginUrl
     * @return
     */
    public FormLoginConfigurator loginUrl(String loginUrl) {
        loginProcessingUrl(loginUrl);
        return loginPage(loginUrl);
    }

    public FormLoginConfigurator loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
        usernamePasswordFilter.setFilterProcessesUrl(loginProcessingUrl);
        return this;
    }

    public FormLoginConfigurator loginPage(String loginPage) {
        this.loginPage = loginPage;
        this.authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(loginPage);
        return this;
    }

    public FormLoginConfigurator usernameParameter(String usernameParameter) {
        usernamePasswordFilter.setUsernameParameter(usernameParameter);
        return this;
    }

    public FormLoginConfigurator passwordParameter(String passwordParameter) {
        usernamePasswordFilter.setPasswordParameter(passwordParameter);
        return this;
    }

    /**
     * Equivalent of invoking permitAll(true)
     * @return
     */
    public FormLoginConfigurator permitAll() {
        return permitAll(true);
    }

    /**
     * Ensures the urls for {@link #failureUrl(String)} and
     * {@link #loginUrl(String)} are granted access to any user.
     *
     * @param permitAll
     * @return
     */
    public FormLoginConfigurator permitAll(boolean permitAll) {
        this.permitAll = permitAll;
        return this;
    }

    public FormLoginConfigurator failureUrl(String failureUrl) {
        this.failureUrl = failureUrl;
        return failureHandler(new SimpleUrlAuthenticationFailureHandler(failureUrl));
    }

    public FormLoginConfigurator failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }
}

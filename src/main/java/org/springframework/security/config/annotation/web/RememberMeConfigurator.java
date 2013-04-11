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

import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.config.annotation.AbstractSecurityConfigurator;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;

/**
 * @author Rob Winch
 *
 */
public class RememberMeConfigurator extends AbstractSecurityConfigurator<DefaultSecurityFilterChain,HttpConfiguration> {
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private DataSource dataSource;
    private String key;
    private RememberMeServices rememberMeServices;
    private LogoutHandler logoutHandler;
    private String rememberMeParameter = "remember-me";
    private String rememberMeCookieName = "remember-me";

    public RememberMeConfigurator authenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        return this;
    }

    // FIXME what if DataSource is not on the classpath
    public RememberMeConfigurator dataSource(DataSource dataSource) {
        this.dataSource = dataSource;
        return this;
    }

    public RememberMeConfigurator rememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = rememberMeServices;
        return this;
    }

    @Override
    protected void doInit(HttpConfiguration http) throws Exception {
        String key = getKey();
        RememberMeServices rememberMeServices = createRememberMeServices(http,key);
        http.setSharedObject(RememberMeServices.class, rememberMeServices);
        LogoutConfigurator logoutConfigurator = http.getConfigurator(LogoutConfigurator.class);
        logoutConfigurator.addLogoutHandler(logoutHandler);

        RememberMeAuthenticationProvider authenticationProvider = new RememberMeAuthenticationProvider(key);
        http.authenticationProvider(authenticationProvider);
    }

    private RememberMeServices createRememberMeServices(HttpConfiguration http, String key) {
        if(rememberMeServices != null) {
            if(rememberMeServices instanceof LogoutHandler && logoutHandler == null) {
                this.logoutHandler = (LogoutHandler) rememberMeServices;
            }
            return rememberMeServices;
        }
        UserDetailsService userDetailsService = getUserDetailsService(http);
        TokenBasedRememberMeServices tokenRememberMeServices = new TokenBasedRememberMeServices(key, userDetailsService);
        tokenRememberMeServices.setParameter(rememberMeParameter);
        tokenRememberMeServices.setCookieName(rememberMeCookieName);
        logoutHandler = tokenRememberMeServices;
        rememberMeServices = tokenRememberMeServices;
        return tokenRememberMeServices;
    }

    @Override
    protected void doConfigure(HttpConfiguration http)
            throws Exception {
        RememberMeAuthenticationFilter rememberMeFilter = new RememberMeAuthenticationFilter(http.authenticationManager(), rememberMeServices);
        http.addFilter(rememberMeFilter);
    }

    private UserDetailsService getUserDetailsService(HttpConfiguration http) {
        return http.getSharedObject(UserDetailsService.class);
    }

    private String getKey() {
        if(key == null) {
            key = UUID.randomUUID().toString();
        }
        return key;
    }
}

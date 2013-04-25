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

import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.config.annotation.AbstractSecurityConfigurator;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;

/**
 * @author Rob Winch
 *
 */
public class RememberMeConfigurator extends AbstractSecurityConfigurator<DefaultSecurityFilterChain,HttpConfigurator> {
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private String key;
    private RememberMeServices rememberMeServices;
    private LogoutHandler logoutHandler;
    private String rememberMeParameter = "remember-me";
    private String rememberMeCookieName = "remember-me";
    private PersistentTokenRepository tokenRepository;
    private UserDetailsService userDetailsService;
    private Integer tokenValiditySeconds;
    private Boolean useSecureCookie;

    public RememberMeConfigurator tokenValiditySeconds(int tokenValiditySeconds) {
        this.tokenValiditySeconds = tokenValiditySeconds;
        return this;
    }

    public RememberMeConfigurator useSecureCookie(boolean useSecureCookie) {
        this.useSecureCookie = useSecureCookie;
        return this;
    }

    public RememberMeConfigurator userDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
        return this;
    }

    public RememberMeConfigurator tokenRepository(PersistentTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
        return this;
    }

    public RememberMeConfigurator key(String key) {
        this.key = key;
        return this;
    }

    public RememberMeConfigurator authenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        return this;
    }

    public RememberMeConfigurator rememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = rememberMeServices;
        return this;
    }

    @Override
    protected void doInit(HttpConfigurator http) throws Exception {
        String key = getKey();
        RememberMeServices rememberMeServices = getRememberMeServices(http,key);
        http.setSharedObject(RememberMeServices.class, rememberMeServices);
        LogoutConfigurator logoutConfigurator = http.getConfigurator(LogoutConfigurator.class);
        logoutConfigurator.addLogoutHandler(logoutHandler);

        RememberMeAuthenticationProvider authenticationProvider = new RememberMeAuthenticationProvider(key);
        http.authenticationProvider(authenticationProvider);
    }

    private RememberMeServices getRememberMeServices(HttpConfigurator http, String key) {
        if(rememberMeServices != null) {
            if(rememberMeServices instanceof LogoutHandler && logoutHandler == null) {
                this.logoutHandler = (LogoutHandler) rememberMeServices;
            }
            return rememberMeServices;
        }
        AbstractRememberMeServices tokenRememberMeServices = createRememberMeServices(http,key);
        tokenRememberMeServices.setParameter(rememberMeParameter);
        tokenRememberMeServices.setCookieName(rememberMeCookieName);
        if(tokenValiditySeconds != null) {
            tokenRememberMeServices.setTokenValiditySeconds(tokenValiditySeconds);
        }
        if(useSecureCookie != null) {
            tokenRememberMeServices.setUseSecureCookie(useSecureCookie);
        }
        logoutHandler = tokenRememberMeServices;
        rememberMeServices = tokenRememberMeServices;
        return tokenRememberMeServices;
    }

    private AbstractRememberMeServices createRememberMeServices(HttpConfigurator http,
            String key) {
        return tokenRepository == null ? createTokenBasedRememberMeServices(http, key) : createPersistentRememberMeServices(http, key);
    }

    private AbstractRememberMeServices createTokenBasedRememberMeServices(HttpConfigurator http,
            String key) {
        UserDetailsService userDetailsService = getUserDetailsService(http);
        return new TokenBasedRememberMeServices(key, userDetailsService);
    }

    private AbstractRememberMeServices createPersistentRememberMeServices(
            HttpConfigurator http, String key) {
        UserDetailsService userDetailsService = getUserDetailsService(http);
        return new PersistentTokenBasedRememberMeServices(key, userDetailsService, tokenRepository);
    }

    @Override
    protected void doConfigure(HttpConfigurator http)
            throws Exception {
        RememberMeAuthenticationFilter rememberMeFilter = new RememberMeAuthenticationFilter(http.authenticationManager(), rememberMeServices);
        if(authenticationSuccessHandler != null) {
            rememberMeFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        }
        http.addFilter(rememberMeFilter);
    }

    private UserDetailsService getUserDetailsService(HttpConfigurator http) {
        return userDetailsService == null ? http.getSharedObject(UserDetailsService.class) : userDetailsService;
    }

    private String getKey() {
        if(key == null) {
            key = UUID.randomUUID().toString();
        }
        return key;
    }
}

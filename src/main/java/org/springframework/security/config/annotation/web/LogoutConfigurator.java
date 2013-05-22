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

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

public class LogoutConfigurator extends SecurityConfiguratorAdapter<DefaultSecurityFilterChain,HttpConfiguration> {
    private List<LogoutHandler> logoutHandlers = new ArrayList<LogoutHandler>();
    private SecurityContextLogoutHandler contextLogoutHandler = new SecurityContextLogoutHandler();
    private String logoutSuccessUrl = "/login?logout";
    private LogoutSuccessHandler logoutSuccessHandler;
    private String logoutUrl = "/logout";
    private boolean permitAll;

    private LogoutFilter createLogoutFilter() throws Exception {
        logoutHandlers.add(contextLogoutHandler);
        LogoutHandler[] handlers = logoutHandlers.toArray(new LogoutHandler[logoutHandlers.size()]);
        LogoutFilter result = new LogoutFilter(getLogoutSuccessHandler(), handlers);
        result.setFilterProcessesUrl(logoutUrl);
        result.afterPropertiesSet();
        return result;
    }

    public LogoutConfigurator permitAll() {
        return permitAll(true);
    }

    public LogoutConfigurator permitAll(boolean permitAll) {
        this.permitAll = permitAll;
        return this;
    }

    public LogoutConfigurator addLogoutHandler(LogoutHandler logoutHandler) {
        this.logoutHandlers.add(logoutHandler);
        return this;
    }

    public LogoutConfigurator invalidateHttpSession(boolean invalidateHttpSession) {
        contextLogoutHandler.setInvalidateHttpSession(invalidateHttpSession);
        return this;
    }

    public LogoutConfigurator logoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
        return this;
    }

    public LogoutConfigurator logoutSuccessUrl(String logoutSuccessUrl) {
        this.logoutSuccessUrl = logoutSuccessUrl;
        return this;
    }

    public LogoutConfigurator logoutSuccessHandler(LogoutSuccessHandler logoutSuccessHandler) {
        this.logoutSuccessHandler = logoutSuccessHandler;
        return this;
    }

    private LogoutSuccessHandler getLogoutSuccessHandler() {
        if(logoutSuccessHandler != null) {
            return logoutSuccessHandler;
        }
        SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
        logoutSuccessHandler.setDefaultTargetUrl(logoutSuccessUrl);
        return logoutSuccessHandler;
    }

    public LogoutConfigurator deleteCookies(String... cookieNamesToClear) {
        return addLogoutHandler(new CookieClearingLogoutHandler(cookieNamesToClear));
    }

    String getLogoutSuccesUrl() {
        return logoutSuccessHandler == null ? logoutSuccessUrl : null;
    }

    String getLogoutUrl() {
        return logoutUrl;
    }

    @Override
    public void init(HttpConfiguration http) throws Exception {
        if(permitAll) {
            PermitAllSupport.permitAll(http, this.logoutUrl, this.logoutSuccessUrl);
        }
    }

    @Override
    public void configure(HttpConfiguration http) throws Exception {
        LogoutFilter logoutFilter = createLogoutFilter();
        http.addFilter(logoutFilter);
    }
}
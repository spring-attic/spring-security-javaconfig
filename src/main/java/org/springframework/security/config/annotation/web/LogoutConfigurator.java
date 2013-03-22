package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.config.annotation.AbstractSecurityConfigurator;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

public class LogoutConfigurator extends AbstractSecurityConfigurator<DefaultSecurityFilterChain,HttpConfiguration> {
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

    protected void doInit(HttpConfiguration builder)
            throws Exception {
        if(permitAll) {
            PermitAllSupport.permitAll(builder, this.logoutUrl, this.logoutSuccessUrl);
        }
    }

    protected void doConfigure(HttpConfiguration builder)
            throws Exception {
        LogoutFilter logoutFilter = createLogoutFilter();
        builder.addFilter(logoutFilter);
    }
}
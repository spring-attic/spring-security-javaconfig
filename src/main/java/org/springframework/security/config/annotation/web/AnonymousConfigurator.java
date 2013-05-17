package org.springframework.security.config.annotation.web;

import java.util.List;
import java.util.UUID;

import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.AbstractConfigurator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

public class AnonymousConfigurator extends AbstractConfigurator<DefaultSecurityFilterChain,HttpConfigurator> {
    private String key;
    private AuthenticationProvider authenticationProvider;
    private AnonymousAuthenticationFilter authenticationFilter;
    private Object principal = "anonymousUser";
    private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");

    @Override
    public void init(HttpConfigurator http)
            throws Exception {
        if(authenticationProvider == null) {
            authenticationProvider = new AnonymousAuthenticationProvider(getKey());
        }
        if(authenticationFilter == null) {
            authenticationFilter = new AnonymousAuthenticationFilter(getKey(), principal, authorities);
        }
        http.authenticationProvider(authenticationProvider);
    }

    @Override
    public void configure(HttpConfigurator http) throws Exception {
        authenticationFilter.afterPropertiesSet();
        http.addFilter(authenticationFilter);
    }

    public HttpConfigurator disable() {
        return and().removeConfigurator(getClass()).and();
    }

    public AnonymousConfigurator key(String key) {
        this.key = key;
        return this;
    }

    public AnonymousConfigurator principal(Object principal) {
        this.principal = principal;
        return this;
    }

    public AnonymousConfigurator authorities(List<GrantedAuthority> authorities) {
        this.authorities = authorities;
        return this;
    }

    public AnonymousConfigurator authorities(String... authorities) {
        return authorities(AuthorityUtils.createAuthorityList(authorities));
    }

    public AnonymousConfigurator authenticationProvider(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
        return this;
    }

    public AnonymousConfigurator authenticationFilter(AnonymousAuthenticationFilter authenticationFilter) {
        this.authenticationFilter = authenticationFilter;
        return this;
    }

    private String getKey() {
        if(key == null) {
            key = UUID.randomUUID().toString();
        }
        return key;
    }
}

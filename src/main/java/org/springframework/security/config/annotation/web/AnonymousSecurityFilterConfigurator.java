package org.springframework.security.config.annotation.web;

import java.util.List;
import java.util.UUID;

import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

public class AnonymousSecurityFilterConfigurator implements SecurityConfigurator<SecurityFilterChainSecurityBuilder> {
    private String key;
    private AuthenticationProvider authenticationProvider;
    private AnonymousAuthenticationFilter authenticationFilter;
    private Object principal = "anonymousUser";
    private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");

    @Override
    public void init(SecurityFilterChainSecurityBuilder builder)
            throws Exception {
        if(authenticationProvider == null) {
            authenticationProvider = new AnonymousAuthenticationProvider(getKey());
        }
        if(authenticationFilter == null) {
            authenticationFilter = new AnonymousAuthenticationFilter(getKey(), principal, authorities);
        }
        builder.getAuthenticationBuilder().authenticationProvider(authenticationProvider);
    }

    public AnonymousSecurityFilterConfigurator key(String key) {
        this.key = key;
        return this;
    }

    public AnonymousSecurityFilterConfigurator principal(Object principal) {
        this.principal = principal;
        return this;
    }

    public AnonymousSecurityFilterConfigurator authorities(List<GrantedAuthority> authorities) {
        this.authorities = authorities;
        return this;
    }

    public AnonymousSecurityFilterConfigurator authorities(String... authorities) {
        return authorities(AuthorityUtils.createAuthorityList(authorities));
    }

    public AnonymousSecurityFilterConfigurator authenticationProvider(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
        return this;
    }

    public AnonymousSecurityFilterConfigurator authenticationFilter(AnonymousAuthenticationFilter authenticationFilter) {
        this.authenticationFilter = authenticationFilter;
        return this;
    }

    private String getKey() {
        if(key == null) {
            key = UUID.randomUUID().toString();
        }
        return key;
    }
    @Override
    public void configure(SecurityFilterChainSecurityBuilder builder)
            throws Exception {
        authenticationFilter.afterPropertiesSet();
        builder.addFilter(authenticationFilter);
    }
}

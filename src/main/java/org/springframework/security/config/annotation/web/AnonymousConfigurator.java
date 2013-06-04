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

import java.util.List;
import java.util.UUID;

import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/**
 * Configures Anonymous authentication (i.e. populate an {@link Authentication} that represents an anonymous user
 * instead of having a null value) for an {@link HttpConfiguration}. Specifically this will configure an
 * {@link AnonymousAuthenticationFilter} and an {@link AnonymousAuthenticationProvider}. All properties have reasonable
 * defaults, so no additional configuration is required other than applying this {@link SecurityConfigurator}.
 *
 * @author  Rob Winch
 * @since  3.2
 */
public final class AnonymousConfigurator extends SecurityConfiguratorAdapter<DefaultSecurityFilterChain,HttpConfiguration> {
    private String key;
    private AuthenticationProvider authenticationProvider;
    private AnonymousAuthenticationFilter authenticationFilter;
    private Object principal = "anonymousUser";
    private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");

    /**
     * Creates a new instance
     * @see HttpConfiguration#anonymous()
     */
    AnonymousConfigurator() {
    }

    /**
     * Disables anonymous authentication.
     *
     * @return the {@link HttpConfiguration} since no further customization of anonymous authentication would be
     *         meaningful.
     */
    public HttpConfiguration disable() {
        return and().removeConfigurator(getClass()).and();
    }

    /**
     * Sets the key to identify tokens created for anonymous authentication. Default is a secure randomly generated
     * key.
     *
     * @param key the key to identify tokens created for anonymous authentication. Default is a secure randomly generated
     *            key.
     * @return  the {@link AnonymousConfigurator} for further customization of anonymous authentication
     */
    public AnonymousConfigurator key(String key) {
        this.key = key;
        return this;
    }

    /**
     * Sets the principal for {@link Authentication} objects of anonymous users
     *
     * @param principal used for the {@link Authentication} object of anonymous users
     * @return  the {@link AnonymousConfigurator} for further customization of anonymous authentication
     */
    public AnonymousConfigurator principal(Object principal) {
        this.principal = principal;
        return this;
    }

    /**
     * Sets the {@link org.springframework.security.core.Authentication#getAuthorities()} for anonymous users
     *
     * @param authorities Sets the {@link org.springframework.security.core.Authentication#getAuthorities()} for anonymous users
     * @return the {@link AnonymousConfigurator} for further customization of anonymous authentication
     */
    public AnonymousConfigurator authorities(List<GrantedAuthority> authorities) {
        this.authorities = authorities;
        return this;
    }

    /**
     * Sets the {@link org.springframework.security.core.Authentication#getAuthorities()} for anonymous users
     *
     * @param authorities Sets the {@link org.springframework.security.core.Authentication#getAuthorities()} for
     *                    anonymous users (i.e. "ROLE_ANONYMOUS")
     * @return the {@link AnonymousConfigurator} for further customization of anonymous authentication
     */
    public AnonymousConfigurator authorities(String... authorities) {
        return authorities(AuthorityUtils.createAuthorityList(authorities));
    }

    /**
     * Sets the {@link AuthenticationProvider} used to validate an anonymous user. If this is set, no attributes
     * on the {@link AnonymousConfigurator} will be set on the {@link AuthenticationProvider}.
     *
     * @param authenticationProvider the {@link AuthenticationProvider} used to validate an anonymous user. Default is
     *                               {@link AnonymousAuthenticationProvider}
     *
     * @return the {@link AnonymousConfigurator} for further customization of anonymous authentication
     */
    public AnonymousConfigurator authenticationProvider(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
        return this;
    }

    /**
     * Sets the {@link AnonymousAuthenticationFilter} used to populate an anonymous user. If this is set, no attributes
     * on the {@link AnonymousConfigurator} will be set on the {@link AnonymousAuthenticationFilter}.
     *
     * @param authenticationFilter the {@link AnonymousAuthenticationFilter} used to populate an anonymous user.
     *
     * @return the {@link AnonymousConfigurator} for further customization of anonymous authentication
     */
    public AnonymousConfigurator authenticationFilter(AnonymousAuthenticationFilter authenticationFilter) {
        this.authenticationFilter = authenticationFilter;
        return this;
    }

    @Override
    public void init(HttpConfiguration http)
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
    public void configure(HttpConfiguration http) throws Exception {
        authenticationFilter.afterPropertiesSet();
        http.addFilter(authenticationFilter);
    }

    private String getKey() {
        if(key == null) {
            key = UUID.randomUUID().toString();
        }
        return key;
    }
}

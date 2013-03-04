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
package org.springframework.security.config.annotation.authentication;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */

public class AuthenticationManagerSecurityBuilder implements SecurityBuilder<AuthenticationManager> {
    private List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
    private AuthenticationManager parentAuthenticationManager;

    public AuthenticationManager build() throws Exception {
        ProviderManager providerManager = new ProviderManager(providers, parentAuthenticationManager);
        providerManager.afterPropertiesSet();
        return providerManager;
    }

    public AuthenticationManagerSecurityBuilder parentAuthenticationManager(AuthenticationManager parentAuthenticationManager) {
        this.parentAuthenticationManager = parentAuthenticationManager;
        return this;
    }

    public AuthenticationManagerSecurityBuilder authenticationProvider(AuthenticationProvider authenticationProvider) throws Exception {
        providers.add(authenticationProvider);
        return this;
    }

    public AuthenticationManagerSecurityBuilder authenticationProvider(SecurityBuilder<? extends AuthenticationProvider> authenticationProviderBuilder) throws Exception {
        return authenticationProvider(authenticationProviderBuilder.build());
    }

    public AuthenticationManagerSecurityBuilder userDetails(SecurityBuilder<? extends UserDetailsService> userDetailsServiceBuilder) throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsServiceBuilder.build());
        providers.add(provider);
        return this;
    }
}

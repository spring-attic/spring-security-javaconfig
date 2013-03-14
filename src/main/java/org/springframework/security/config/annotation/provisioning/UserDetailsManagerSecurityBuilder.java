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
package org.springframework.security.config.annotation.provisioning;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.UserDetailsServiceSecurityBuilder;
import org.springframework.security.config.annotation.authentication.UserSecurityBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class UserDetailsManagerSecurityBuilder<T extends UserDetailsManagerSecurityBuilder<T>> extends UserDetailsServiceSecurityBuilder<UserDetailsManager> {
    private List<SecurityBuilder<UserDetails>> userBuilders = new ArrayList<SecurityBuilder<UserDetails>>();
    private AuthenticationManager manager;

    public UserDetailsManagerSecurityBuilder(UserDetailsManager userDetailsManager) {
        super(userDetailsManager);
    }

    public AuthenticationManager build() throws Exception {
        if(manager != null) {
            return manager;
        }
        for(SecurityBuilder<UserDetails> userBuilder : userBuilders) {
            userDetailsService.createUser(userBuilder.build());
        }
        manager = super.build();
        return manager;
    }

    public final UserSecurityBuilder<T> withUser(String username) {
        UserSecurityBuilder<T> userBuilder = new UserSecurityBuilder<T>((T)this);
        userBuilder.username(username);
        this.userBuilders.add(userBuilder);
        return userBuilder;
    }

    public static class UserSecurityBuilder<T> implements SecurityBuilder<UserDetails> {
        private String username;
        private String password;
        private List<GrantedAuthority> authorities;
        private boolean accountNonExpired = true;
        private boolean accountNonLocked = true;
        private boolean credentialsNonExpired = true;
        private boolean enabled = true;
        private final T builder;

        private UserSecurityBuilder(T builder) {
            this.builder = builder;
        }

        public T and() {
            return builder;
        }

        public UserSecurityBuilder<T> username(String username) {
            this.username = username;
            return this;
        }

        public UserSecurityBuilder<T> password(String password) {
            this.password = password;
            return this;
        }

        public UserSecurityBuilder<T> roles(String... roles) {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(roles.length);
            for(String role : roles) {
                authorities.add(new SimpleGrantedAuthority("ROLE_"+role));
            }
            this.authorities = authorities;
            return this;
        }

        public UserSecurityBuilder<T> authorities(String... authorities) {
            this.authorities = AuthorityUtils.createAuthorityList(authorities);
            return this;
        }

        public UserDetails build() {
            return new User(username, password, enabled, accountNonExpired,
                    credentialsNonExpired, accountNonLocked, authorities);
        }
    }
}

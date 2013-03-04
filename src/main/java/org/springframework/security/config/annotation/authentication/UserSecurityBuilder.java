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

import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class UserSecurityBuilder implements SecurityBuilder<UserDetails> {
    private String username;
    private String password;
    private List<GrantedAuthority> authorities;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;

    public UserSecurityBuilder username(String username) {
        this.username = username;
        return this;
    }

    public UserSecurityBuilder password(String password) {
        this.password = password;
        return this;
    }

    public UserSecurityBuilder roles(String... roles) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(roles.length);
        for(String role : roles) {
            authorities.add(new SimpleGrantedAuthority("ROLE_"+role));
        }
        this.authorities = authorities;
        return this;
    }

    public UserSecurityBuilder authorities(String... authorities) {
        this.authorities = AuthorityUtils.createAuthorityList(authorities);
        return this;
    }

    public UserDetails build() {
        return new User(username, password, enabled, accountNonExpired,
                credentialsNonExpired, accountNonLocked, authorities);
    }

    public static UserSecurityBuilder user(String username) {
        UserSecurityBuilder result = new UserSecurityBuilder();
        result.username(username);
        return result;
    }
}
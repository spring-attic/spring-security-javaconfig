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

import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.UserDetailsServiceSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class UserDetailsManagerSecurityBuilder<T extends UserDetailsManagerSecurityBuilder<T>> extends UserDetailsServiceSecurityBuilder<UserDetailsManager> {
    private List<SecurityBuilder<UserDetails>> userBuilders = new ArrayList<SecurityBuilder<UserDetails>>();

    public UserDetailsManagerSecurityBuilder(UserDetailsManager userDetailsManager) {
        super(userDetailsManager);
    }

    @Override
    public UserDetailsManager build() throws Exception {
        for(SecurityBuilder<UserDetails> userBuilder : userBuilders) {
            userDetailsService.createUser(userBuilder.build());
        }
        return super.build();
    }

    public final T withUsers(SecurityBuilder<UserDetails>... userBuilders) throws Exception {
        for(SecurityBuilder<UserDetails> userBuilder : userBuilders) {
            this.userBuilders.add(userBuilder);
        }
        return (T) this;
    }
}

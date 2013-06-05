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
package org.springframework.security.config.annotation.authentication;

import org.springframework.security.config.annotation.SecurityConfigurator;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Allows configuring a {@link UserDetailsService} within a {@link AuthenticationManagerBuilder}.
 *
 * @author Rob Winch
 * @since 3.2
 *
 * @param <C> the {@link SecurityConfigurator} (or this)
 * @param <T> the type of UserDetailsService being used to allow for returning the concrete UserDetailsService.
 */
public class UserDetailsServiceConfigurator<C extends DaoAuthenticationRegitry<C>,T extends UserDetailsService> extends DaoAuthenticationConfigurator<C,T> {

    /**
     * Creates a new instance
     * @param userDetailsService the {@link UserDetailsService} that should be used
     */
    public UserDetailsServiceConfigurator(T userDetailsService) {
        super(userDetailsService);
    }

    @Override
    public void configure(AuthenticationManagerBuilder builder) throws Exception {
        initUserDetailsService();

        super.configure(builder);
    }

    /**
     * Allows subclasses to initialize the {@link UserDetailsService}. For example, it might add users, initialize
     * schema, etc.
     */
    protected void initUserDetailsService() throws Exception {}
}

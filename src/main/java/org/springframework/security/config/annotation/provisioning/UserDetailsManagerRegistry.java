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
package org.springframework.security.config.annotation.provisioning;

import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.authentication.DaoAuthenticationRegistry;
import org.springframework.security.config.annotation.provisioning.UserDetailsManagerConfigurator.UserDetailsBuilder;
import org.springframework.security.provisioning.UserDetailsManager;

/**
 * Allows populating a {@link AuthenticationmanagerBuilder} with a {@link UserDetailsManager} and populating the
 * {@link UserDetailsManager} with users.
 *
 * @author Rob Winch
 *
 * @param <T> the type for "this" to allow for returning sub interfaces/classes that allow method chaining.
 */
public interface UserDetailsManagerRegistry<T extends UserDetailsManagerRegistry<T>> extends DaoAuthenticationRegistry<T> {

    /**
     * Adds a {@link org.springframework.security.core.userdetails.UserDetails} that can be authenticated with
     *
     * @param username the username for this user. Cannot be null.
     * @return a {@link UserDetailsBuilder} that can be used for further customization of the
     *         {@link org.springframework.security.core.userdetails.UserDetails}
     */
    UserDetailsBuilder<T> withUser(String username);

    /**
     * Allows method chaining by returning the {@link AuthenticationRegistry} for additional customization.
     *
     * @return the {@link AuthenticationRegistry} for additional customization.
     * @throws Exception
     */
    AuthenticationRegistry and() throws Exception;
}
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

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.config.annotation.authentication.UserDetailsServiceConfigurator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.Assert;

/**
 * Base class for populating an
 * {@link org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder} with a
 * {@link UserDetailsManager}.
 *
 * @author Rob Winch
 * @since 3.2
 */
class UserDetailsManagerConfigurator<T extends UserDetailsManagerRegistry<T>> extends
        UserDetailsServiceConfigurator<UserDetailsManager> implements UserDetailsManagerRegistry<T> {

    private final List<UserDetailsBuilder<T>> userBuilders = new ArrayList<UserDetailsBuilder<T>>();

    public UserDetailsManagerConfigurator(UserDetailsManager userDetailsManager) {
        super(userDetailsManager);
    }

    /**
     * Populates the users that have been added.
     *
     * @throws Exception
     */
    @Override
    protected void initUserDetailsService() throws Exception {
        for(UserDetailsBuilder<T> userBuilder : userBuilders) {
            getUserDetailsService().createUser(userBuilder.build());
        }
    }

    /**
     * Allows adding a user to the {@link UserDetailsManager} that is being created. This method can be invoked
     * multiple times to add multiple users.
     *
     * @param username the username for the user being added. Cannot be null.
     * @return
     */
    @Override
    public final UserDetailsBuilder<T> withUser(String username) {
        UserDetailsBuilder<T> userBuilder = new UserDetailsBuilder<T>((T)this);
        userBuilder.username(username);
        this.userBuilders.add(userBuilder);
        return userBuilder;
    }

    /**
     * Builds the user to be added. At minimum the username, password, and authorities should provided. The remaining
     * attributes have reasonable defaults.
     *
     * @param <T> the type of {@link UserDetailsManagerRegistry} to return for chaining methods.
     */
    public static class UserDetailsBuilder<T extends UserDetailsManagerRegistry<T>> {
        private String username;
        private String password;
        private List<GrantedAuthority> authorities;
        private boolean accountNonExpired = true;
        private boolean accountNonLocked = true;
        private boolean credentialsNonExpired = true;
        private boolean enabled = true;
        private final T builder;

        /**
         * Creates a new instance
         * @param builder the builder to return
         */
        private UserDetailsBuilder(T builder) {
            this.builder = builder;
        }

        /**
         * Returns the {@link UserDetailsManagerRegistry} for method chaining (i.e. to add another user)
         *
         * @return the {@link UserDetailsManagerRegistry} for method chaining (i.e. to add another user)
         */
        public T and() {
            return builder;
        }

        /**
         * Populates the username. This attribute is required.
         *
         * @param username the username. Cannot be null.
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         */
        private UserDetailsBuilder<T> username(String username) {
            Assert.notNull(username, "username cannot be null");
            this.username = username;
            return this;
        }

        /**
         * Populates the password. This attribute is required.
         *
         * @param password the password. Cannot be null.
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         */
        public UserDetailsBuilder<T> password(String password) {
            Assert.notNull(password, "password cannot be null");
            this.password = password;
            return this;
        }

        /**
         * Populates the roles. This method is a shortcut for calling {@link #authorities(String...)}, but automatically
         * prefixes each entry with "ROLE_". This means the following:
         *
         * <code>
         *     builder.roles("USER","ADMIN");
         * </code>
         *
         * is equivalent to
         *
         * <code>
         *     builder.authorities("ROLE_USER","ROLE_ADMIN");
         * </code>
         *
         * <p>This attribute is required, but can also be populated with {@link #authorities(String...)}.</p>
         *
         * @param roles the roles for this user (i.e. USER, ADMIN, etc). Cannot be null, contain null values or start
         *              with "ROLE_"
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         */
        public UserDetailsBuilder<T> roles(String... roles) {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(roles.length);
            for(String role : roles) {
                Assert.isTrue(!role.startsWith("ROLE_"), role + " cannot start with ROLE_ (it is automatically added)");
                authorities.add(new SimpleGrantedAuthority("ROLE_"+role));
            }
            this.authorities = authorities;
            return this;
        }


        /**
         * Populates the authorities. This attribute is required.
         *
         * @param authorities the roles for this user (i.e. ROLE_USER, ROLE_ADMIN, etc). Cannot be null, or contain null
         *                    values
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         * @see #roles(String...)
         */
        public UserDetailsBuilder<T> authorities(String... authorities) {
            this.authorities = AuthorityUtils.createAuthorityList(authorities);
            return this;
        }

        private UserDetails build() {
            return new User(username, password, enabled, accountNonExpired,
                    credentialsNonExpired, accountNonLocked, authorities);
        }
    }
}

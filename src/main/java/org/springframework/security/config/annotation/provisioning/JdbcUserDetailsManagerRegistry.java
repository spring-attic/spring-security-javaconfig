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

import javax.sql.DataSource;

/**
 * Configures an {@link org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder} to
 * have JDBC authentication. It also allows easily adding users to the database used for authentication and setting up
 * the schema.
 *
 * <p>
 * The only required method is the {@link #dataSource(javax.sql.DataSource)} all other methods have reasonable defaults.
 * </p>
 *
 * @param <T> Allows to parameterize (this) so that the {@link JdbcUserDetailsManagerRegistry} can be returned when
 *           using method chaining.
 *
 * @author Rob Winch
 * @since 3.2
 */
public interface JdbcUserDetailsManagerRegistry<T extends JdbcUserDetailsManagerRegistry<T>> extends
        UserDetailsManagerRegistry<T> {

    /**
     * Populates the {@link DataSource} to be used. This is the only required attribute.
     *
     * @param dataSource the {@link DataSource} to be used. Cannot be null.
     * @return
     * @throws Exception
     */
    JdbcUserDetailsManagerRegistry<T> dataSource(DataSource dataSource) throws Exception;

    /**
     * Sets the query to be used for finding a user by their username. For example:
     *
     * <code>
     *     select username,password,enabled from users where username = ?
     * </code>
     * @param query  The query to use for selecting the username, password, and if the user is enabled by username.
     *               Must contain a single parameter for the username.
     * @return The {@link JdbcUserDetailsManagerRegistry} used for additional customizations
     * @throws Exception
     */
    JdbcUserDetailsManagerRegistry<T> usersByUsernameQuery(
            String query) throws Exception;

    /**
     * Sets the query to be used for finding a user's authorities by their username. For example:
     *
     * <code>
     *     select username,authority from authorities where username = ?
     * </code>
     *
     * @param query  The query to use for selecting the username, authority  by username.
     *               Must contain a single parameter for the username.
     * @return The {@link JdbcUserDetailsManagerRegistry} used for additional customizations
     * @throws Exception
     */
    JdbcUserDetailsManagerRegistry<T> authoritiesByUsernameQuery(
            String query) throws Exception;

    /**
     * Populates the default schema that allows users and authorities to be stored.
     *
     * @return The {@link JdbcUserDetailsManagerRegistry} used for additional customizations
     */
    JdbcUserDetailsManagerRegistry<T> withDefaultSchema();
}
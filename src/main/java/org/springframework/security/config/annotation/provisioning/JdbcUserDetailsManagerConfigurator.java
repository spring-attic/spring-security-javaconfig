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

import javax.sql.DataSource;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;
import org.springframework.jdbc.datasource.init.DatabasePopulator;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

/**
 * Configures an {@link org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder} to
 * have JDBC authentication. It also allows easily adding users to the database used for authentication and setting up
 * the schema.
 *
 * <p>
 * The only required method is the {@link #dataSource(javax.sql.DataSource)} all other methods have reasonable defaults.
 * </p>
 *
 * @author Rob Winch
 * @since 3.2
 */
public class JdbcUserDetailsManagerConfigurator extends
        UserDetailsManagerConfigurator<JdbcUserDetailsManagerConfigurator> {

    private DataSource dataSource;

    private List<Resource> initScripts = new ArrayList<Resource>();

    private ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();

    public JdbcUserDetailsManagerConfigurator() {
        super(new JdbcUserDetailsManager());
    }


    /**
     * Populates the {@link DataSource} to be used. This is the only required attribute.
     *
     * @param dataSource the {@link DataSource} to be used. Cannot be null.
     * @return
     * @throws Exception
     */
    public JdbcUserDetailsManagerConfigurator dataSource(DataSource dataSource) throws Exception {
        this.dataSource = dataSource;
        getUserDetailsService().setDataSource(dataSource);
        return this;
    }

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
    public JdbcUserDetailsManagerConfigurator usersByUsernameQuery(String query) throws Exception {
        getUserDetailsService().setUsersByUsernameQuery(query);
        return this;
    }

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
    public JdbcUserDetailsManagerConfigurator authoritiesByUsernameQuery(String query) throws Exception {
        getUserDetailsService().setAuthoritiesByUsernameQuery(query);
        return this;
    }

    @Override
    protected void initUserDetailsService() throws Exception {
        if(!initScripts.isEmpty()) {
            initDatabase().afterPropertiesSet();
        }
        super.initUserDetailsService();
    }

    @Override
    protected JdbcUserDetailsManager getUserDetailsService() {
        return (JdbcUserDetailsManager) super.getUserDetailsService();
    }

    /**
     * Populates the default schema that allows users and authorities to be stored.
     *
     * @return The {@link JdbcUserDetailsManagerRegistry} used for additional customizations
     */
    public JdbcUserDetailsManagerConfigurator withDefaultSchema() {
        this.initScripts.add(new ClassPathResource("org/springframework/security/core/userdetails/jdbc/users.ddl"));
        return this;
    }

    protected DatabasePopulator databasePopulator() {
        ResourceDatabasePopulator dbp = new ResourceDatabasePopulator();
        dbp.setScripts(initScripts.toArray(new Resource[initScripts.size()]));
        return dbp;
    }

    private DataSourceInitializer initDatabase() {
        DataSourceInitializer dsi = new DataSourceInitializer();
        dsi.setDatabasePopulator(databasePopulator());
        dsi.setDataSource(dataSource);
        return dsi;
    }
}

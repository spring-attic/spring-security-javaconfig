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

import javax.sql.DataSource;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;
import org.springframework.jdbc.datasource.init.DatabasePopulator;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class JdbcUserDetailsManagerSecurityBuilder extends
        UserDetailsManagerSecurityBuilder<JdbcUserDetailsManagerSecurityBuilder> {

    private final DataSource dataSource;

    private List<Resource> initScripts = new ArrayList<Resource>();

    private ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();

    public JdbcUserDetailsManagerSecurityBuilder(DataSource dataSource) {
        super(jdbcUserDetailsManager(dataSource));
        this.dataSource = dataSource;
    }

    @Override
    public JdbcUserDetailsManager build() throws Exception {
        if(!initScripts.isEmpty()) {
            initDatabase().afterPropertiesSet();
        }
        return (JdbcUserDetailsManager) super.build();
    }

    public JdbcUserDetailsManagerSecurityBuilder usersByUsernameQuery(String query) throws Exception {
        userDetailsService().setUsersByUsernameQuery(query);
        return this;
    }

    public JdbcUserDetailsManagerSecurityBuilder authoritiesByUsernameQuery(String query) throws Exception {
        userDetailsService().setAuthoritiesByUsernameQuery(query);
        return this;
    }

    @Override
    public JdbcUserDetailsManager userDetailsService() throws Exception {
        return (JdbcUserDetailsManager) super.userDetailsService();
    }

    public JdbcUserDetailsManagerSecurityBuilder withDefaultSchema() {
        this.initScripts.add(new ClassPathResource("org/springframework/security/core/userdetails/jdbc/users.ddl"));
        return this;
    }

    private static JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager();
        userDetailsManager.setDataSource(dataSource);
        return userDetailsManager;
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

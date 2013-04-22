package org.springframework.security.config.annotation.provisioning;

import javax.sql.DataSource;


public interface JdbcUserDetailsManagerRegistry<T extends JdbcUserDetailsManagerRegistry<T>> extends UserDetailsManagerRegistry<T> {

    JdbcUserDetailsManagerRegistry<T> dataSource(DataSource dataSource) throws Exception;

    JdbcUserDetailsManagerRegistry<T> usersByUsernameQuery(
            String query) throws Exception;

    JdbcUserDetailsManagerRegistry<T> authoritiesByUsernameQuery(
            String query) throws Exception;

    JdbcUserDetailsManagerRegistry<T> withDefaultSchema();
}
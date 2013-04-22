package org.springframework.security.config.annotation.provisioning;


public interface JdbcUserDetailsManagerRegistry<T extends JdbcUserDetailsManagerRegistry<T>> extends UserDetailsManagerRegistry<T> {

	JdbcUserDetailsManagerRegistry<T> usersByUsernameQuery(
			String query) throws Exception;

	JdbcUserDetailsManagerRegistry<T> authoritiesByUsernameQuery(
			String query) throws Exception;

	JdbcUserDetailsManagerRegistry<T> withDefaultSchema();
}
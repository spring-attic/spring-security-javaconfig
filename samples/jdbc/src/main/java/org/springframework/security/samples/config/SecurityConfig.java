package org.springframework.security.samples.config;

import static org.springframework.security.config.annotation.web.WebSecurityConfigurators.*;
import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.provisioning.JdbcUserDetailsManagerSecurityBuilder;
import org.springframework.security.config.annotation.web.DefaultSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizationRegistry;
import org.springframework.security.config.annotation.web.FilterChainProxySecurityBuilder;
import org.springframework.security.config.annotation.web.FormLoginSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity
public class SecurityConfig {
    @Autowired
    private DataSource dataSource;

    @Bean
    public AuthenticationManager authenticationMgr() throws Exception {
        return authenticationManager(userDetailsManager()).build();
    }

    @Bean
    public JdbcUserDetailsManagerSecurityBuilder userDetailsManager() throws Exception {
        return jdbcUserDetailsManager(dataSource).withUsers(
                user("user").password("password").roles("USER"),
                user("admin").password("password").roles("USER", "ADMIN"))
            .withDefaultSchema();
    }

    @Bean
    public FilterChainProxySecurityBuilder builder() throws Exception {
        ExpressionUrlAuthorizationRegistry fiSourceBldr = interceptUrls()
                .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
                .antMatchers("/resources/**","/signup").permitAll()
                .antMatchers("/**").hasRole("USER");

        return new FilterChainProxySecurityBuilder()
            .ignoring(antMatchers("/resources/**"))
            .securityFilterChains(
                new SecurityFilterChainSecurityBuilder(authenticationMgr())
                    .apply(new DefaultSecurityFilterConfigurator(fiSourceBldr).permitAll())
                    .apply(new FormLoginSecurityFilterConfigurator().permitAll()));
    }
}

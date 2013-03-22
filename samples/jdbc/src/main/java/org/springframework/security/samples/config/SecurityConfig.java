package org.springframework.security.samples.config;


import java.util.Date;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizationRegistry;
import org.springframework.security.config.annotation.web.HttpConfiguration;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapater;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapater {
    @Autowired
    private DataSource dataSource;

    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
        ignoredRequests
            .antMatchers("/resources/**");
    }

    protected void registerAuthentication(
            AuthenticationRegistry authenticationRegistry) throws Exception {
        authenticationRegistry
            .jdbcUserDetailsManager(dataSource)
                .withUser("user").password("password").roles("USER").and()
                .withUser("admin").password("password").roles("USER", "ADMIN").and()
                .withDefaultSchema();
    }

    @Bean public Object now() {
        System.out.println(dataSource);
        return new Date();
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizationRegistry interceptUrls) {
        interceptUrls
            .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
            .antMatchers("/resources/**","/signup").permitAll()
            .antMatchers("/**").hasRole("USER");
    }

    protected void configure(
            HttpConfiguration springSecurityFilterChain) throws Exception {
        springSecurityFilterChain
            .formLogin()
            .permitAll();
    }
}

package org.springframework.security.samples.config;

import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*;
import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;
import static org.springframework.security.config.annotation.web.WebSecurityConfigurators.*;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder;
import org.springframework.security.config.annotation.web.DefaultSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder;
import org.springframework.security.config.annotation.web.FilterChainProxySecurityBuilder;
import org.springframework.security.config.annotation.web.FormLoginSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationMgr() throws Exception {
        return authenticationManager(userDetailsManager()).build();
    }

    @Bean
    public InMemoryUserDetailsManagerSecurityBuilder userDetailsManager() throws Exception {
        return inMemoryAuthentication(
          user("user").password("password").roles("USER"),
          user("admin").password("password").roles("USER", "ADMIN"));
    }

    @Bean
    public FilterChainProxySecurityBuilder builder() throws Exception {
        ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder fiSourceBldr = interceptUrls()
            // TODO type safe configAttributes
            .hasRole(antMatchers("/users**","/sessions/**"), "ADMIN")
            .permitAll(antMatchers("/resources/**","/signup"))
            .hasRole(antMatchers("/**"), "USER");

        return new FilterChainProxySecurityBuilder()
            .ignoring(antMatchers("/resources/**"))
            .securityFilterChains(
                new SecurityFilterChainSecurityBuilder(authenticationMgr())
                    .apply(new DefaultSecurityFilterConfigurator(fiSourceBldr).permitAll())
                    .apply(new FormLoginSecurityFilterConfigurator().permitAll()));
    }
}

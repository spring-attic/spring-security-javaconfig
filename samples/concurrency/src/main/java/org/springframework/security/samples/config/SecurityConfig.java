package org.springframework.security.samples.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder;
import org.springframework.security.config.annotation.method.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizations;
import org.springframework.security.config.annotation.web.HttpConfiguration;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapater;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class SecurityConfig extends WebSecurityConfigurerAdapater {
    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
        ignoredRequests
            .antMatchers("/resources/**");
    }

    protected AuthenticationManager authenticationManager(
            AuthenticationBuilder authenticationRegistry) throws Exception {
        return authenticationRegistry
            .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER").and()
                .withUser("admin").password("password").roles("USER", "ADMIN").and()
                .and()
            .build();
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizations interceptUrls) {
        interceptUrls
            .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
            .antMatchers("/resources/**","/signup").permitAll()
            .antMatchers("/**").hasRole("USER");
    }

    protected void configure(
            HttpConfiguration http) throws Exception {
        http
            .formLogin()
                .permitAll()
                .and()
            .sessionManagement()
                .maximumSessions(1)
                .expiredUrl("/login?expired");
    }
}

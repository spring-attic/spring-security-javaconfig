package org.springframework.security.samples.config;

import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.method.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizationRegistry;
import org.springframework.security.config.annotation.web.DefaultSecurityFilterChainBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapater;
import org.springframework.security.web.util.RequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class SecurityConfig extends WebSecurityConfigurerAdapater {
    public List<RequestMatcher> ignoredRequests() {
        return antMatchers("/resources/**");
    }

    protected void registerAuthentication(
            AuthenticationRegistry authenticationRegistry) throws Exception {
        authenticationRegistry
            .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER").and()
                .withUser("admin").password("password").roles("USER", "ADMIN").and();
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizationRegistry interceptUrls) {
        interceptUrls
            .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
            .antMatchers("/resources/**","/signup").permitAll()
            .antMatchers("/**").hasRole("USER");
    }

    protected void configure(
            DefaultSecurityFilterChainBuilder builder) throws Exception {
        builder
            .formLogin()
                .permitAll()
                .and()
            .sessionManagement()
                .maximumSessions(1)
                .expiredUrl("/login?expired");
    }
}

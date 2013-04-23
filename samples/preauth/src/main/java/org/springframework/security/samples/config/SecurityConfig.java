package org.springframework.security.samples.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizations;
import org.springframework.security.config.annotation.web.HttpConfiguration;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
        ignoredRequests
            .antMatchers("/resources/**");
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizations interceptUrls) {
        interceptUrls
            .antMatchers("/login").permitAll()
            .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
            .antMatchers("/resources/**","/signup").permitAll()
            .antMatchers("/**").hasRole("USER");
    }

    protected void configure(HttpConfiguration http) throws Exception {
        http
            .jee()
                .mappableRoles("ROLE_USER","ROLE_ADMIN");
    }

    // FIXME remove registerAuthentication See http://github.com/SpringSource/spring-security-javaconfig/issues/issue/63
    @Override
    protected void registerAuthentication(AuthenticationRegistry registry)
            throws Exception {
        registry
            .inMemoryAuthentication();
    }
}

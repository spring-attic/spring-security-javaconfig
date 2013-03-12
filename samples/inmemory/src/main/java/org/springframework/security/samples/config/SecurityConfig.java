package org.springframework.security.samples.config;

import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*;
import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizationRegistry;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;
import org.springframework.security.config.annotation.web.SimpleWebSecurityConfig;
import org.springframework.security.web.util.RequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends SimpleWebSecurityConfig {
    protected List<RequestMatcher> ignoredRequests() {
        return antMatchers("/resources/**");
    }

    protected AuthenticationManager authenticationMgr() throws Exception {
        return inMemoryAuthentication(
                  user("user").password("password").roles("USER"),
                  user("admin").password("password").roles("USER", "ADMIN")).authenticationManager();
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizationRegistry interceptUrls) {
        interceptUrls
            .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
            .antMatchers("/resources/**","/signup").permitAll()
            .antMatchers("/**").hasRole("USER");
    }

    protected void configure(
            SecurityFilterChainSecurityBuilder springSecurityFilterChain) throws Exception {
        springSecurityFilterChain
            .formLogin()
            .permitAll();
    }
}

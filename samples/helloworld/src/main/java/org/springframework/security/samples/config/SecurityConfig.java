package org.springframework.security.samples.config;

import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void registerAuthentication(AuthenticationRegistry builder) throws Exception {
        builder
            .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER");
    }
}

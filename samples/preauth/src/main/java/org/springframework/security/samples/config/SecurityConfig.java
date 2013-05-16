package org.springframework.security.samples.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.HttpConfigurator;
import org.springframework.security.config.annotation.web.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurityConfiguration builder) throws Exception {
        builder
            .ignoring()
                .antMatchers("/resources/**");
    }

    @Override
    protected void configure(HttpConfigurator http) throws Exception {
        http
            .authorizeUrls()
                .antMatchers("/login").permitAll()
                .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
                .antMatchers("/resources/**","/signup").permitAll()
                .antMatchers("/**").hasRole("USER")
                .and()
            .jee()
                .mappableRoles("ROLE_USER","ROLE_ADMIN");
    }
}

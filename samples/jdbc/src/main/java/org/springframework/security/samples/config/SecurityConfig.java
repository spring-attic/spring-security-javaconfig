package org.springframework.security.samples.config;


import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.HttpConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private DataSource dataSource;

    @Override
    public void configure(WebSecurityConfiguration builder) throws Exception {
        builder
            .ignoring()
                .antMatchers("/resources/**");
    }

    @Override
    protected void registerAuthentication(AuthenticationRegistry builder) throws Exception {
        builder
            .jdbcUserDetailsManager()
                .dataSource(dataSource)
                .withUser("user").password("password").roles("USER").and()
                .withUser("admin").password("password").roles("USER", "ADMIN").and()
                .withDefaultSchema();
    }

    @Override
    protected void configure(HttpConfiguration http) throws Exception {
        http
            .authorizeUrls()
                .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
                .antMatchers("/resources/**","/signup").permitAll()
                .antMatchers("/**").hasRole("USER")
                .and()
            .formLogin()
                .permitAll();
    }
}

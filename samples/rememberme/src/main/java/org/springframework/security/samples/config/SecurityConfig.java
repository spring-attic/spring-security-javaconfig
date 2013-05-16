package org.springframework.security.samples.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.method.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.HttpConfigurator;
import org.springframework.security.config.annotation.web.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    public void configure(WebSecurityConfiguration builder) throws Exception {
        builder
            .ignoring()
                .antMatchers("/resources/**");
    }

    @Override
    protected void registerAuthentication(
            AuthenticationRegistry builder) throws Exception {
        builder
            .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER").and()
                .withUser("admin").password("password").roles("USER", "ADMIN");
    }

    @Override
    protected void configure(HttpConfigurator http) throws Exception {
        http
            .authorizeUrls()
                .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
                .antMatchers("/resources/**","/signup").permitAll()
                .antMatchers("/**").hasRole("USER")
                .and()
            .formLogin()
                .permitAll()
                .and()
            .rememberMe();
    }
}

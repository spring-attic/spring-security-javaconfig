package org.springframework.security.samples.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.HttpConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurityBuilder builder) throws Exception {
        builder
            .ignoring()
                .antMatchers("/resources/**");
    }

    @Override
    protected void registerAuthentication(
            AuthenticationManagerBuilder auth) throws Exception {
        auth
            .apply(new LdapAuthenticationProviderConfigurer())
                .userDnPatterns("uid={0},ou=people")
                .groupSearchBase("ou=groups");
    }

    @Override
    protected void configure(HttpConfiguration http) throws Exception {
        http
            .authorizeUrls()
                .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
                .antMatchers("/resources/**","/signup").permitAll()
                .anyRequest().hasRole("USER")
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll();
    }
}

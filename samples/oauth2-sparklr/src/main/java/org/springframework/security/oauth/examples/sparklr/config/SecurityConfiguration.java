package org.springframework.security.oauth.examples.sparklr.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Bean(name = {"authManager",BeanIds.AUTHENTICATION_MANAGER})
    public AuthenticationManager authManager() throws Exception {
        return new AuthenticationManagerBuilder()
            .inMemoryAuthentication()
                .withUser("marissa").password("koala").roles("USER").and()
                .withUser("paul").password("emu").roles("USER").and()
                .and()
            .build();
    }

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return authManager();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeUrls()
                .antMatchers("/oauth/**").hasRole("USER")
                .anyRequest().permitAll()
                .and()
            .exceptionHandling()
                .accessDeniedPage("/login.jsp?authorization_error=true")
                .and()
            .logout()
                .logoutSuccessUrl("/index.jsp")
                .logoutUrl("/logout.do")
                .and()
            .formLogin()
                    .usernameParameter("j_username")
                    .passwordParameter("j_password")
                    .failureUrl("/login.jsp?authentication_error=true")
                    .loginPage("/login.jsp")
                    .loginProcessingUrl("/login.do");
    }
}

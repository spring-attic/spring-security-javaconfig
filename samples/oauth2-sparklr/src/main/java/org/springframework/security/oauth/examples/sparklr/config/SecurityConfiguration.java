package org.springframework.security.oauth.examples.sparklr.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizations;
import org.springframework.security.config.annotation.web.HttpConfigurator;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Bean(name = {"authManager",BeanIds.AUTHENTICATION_MANAGER})
    public AuthenticationManager authManager() throws Exception {
        return new AuthenticationBuilder()
            .inMemoryAuthentication()
                .withUser("marissa").password("koala").roles("USER").and()
                .withUser("paul").password("emu").roles("USER").and()
                .and()
            .build();
    }

    protected AuthenticationManager authenticationManager() throws Exception {
        return authManager();
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizations interceptUrls) {
        interceptUrls
            .antMatchers("/oauth/**").hasRole("USER")
            .antMatchers("/**").permitAll();
    }

    protected void configure(HttpConfigurator http) throws Exception {
        http
            .applyDefaultConfigurators()
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

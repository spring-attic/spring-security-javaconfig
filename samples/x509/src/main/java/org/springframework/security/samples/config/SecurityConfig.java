package org.springframework.security.samples.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.HttpConfigurator;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
        ignoredRequests
            .antMatchers("/resources/**");
    }

    @Override
    protected void registerAuthentication(AuthenticationRegistry registry)
            throws Exception {
        registry.
            inMemoryAuthentication()
                .withUser("dianne").password("password").roles("USER").and()
                .withUser("rod").password("password").roles("USER","ADMIN").and()
                .withUser("scott").password("password").roles("USER");
    }

    protected void configure(HttpConfigurator http) throws Exception {
        http
            .authorizeUrls()
                .antMatchers("/login").permitAll()
                .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
                .antMatchers("/resources/**","/signup").permitAll()
                .antMatchers("/**").hasRole("USER")
                .and()
            .x509();
    }
}

package org.springframework.security.oauth.examples.config;

import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizationRegistry;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;
import org.springframework.security.config.annotation.web.SimpleWebSecurityConfig;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.util.RequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends SimpleWebSecurityConfig {
    @Autowired
    private OAuth2ClientContextFilter oauth2ClientFilter;

    protected void registerAuthentication(
            AuthenticationRegistry registry) throws Exception {
        registry
            .inMemoryAuthentication()
                .withUser("marissa").password("wombat").roles("USER").and()
                .withUser("sam").password("kangaroo").roles("USER");
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizationRegistry interceptUrls) {
        interceptUrls
            .antMatchers("/sparklr/**","/facebook/**").hasRole("USER")
            .antMatchers("/**");
    }

    protected List<RequestMatcher> ignoredRequests() {
        return antMatchers("/resources/**");
    }

    protected void configure(
            SecurityFilterChainSecurityBuilder builder) throws Exception {
        builder
            .addFilterAfter(oauth2ClientFilter, ExceptionTranslationFilter.class)
            .logout()
                .logoutSuccessUrl("/login.jsp")
                .logoutUrl("/logout.do")
                .permitAll()
                .and()
            .formLogin()
                .loginPage("/login.jsp")
                .loginProcessingUrl("/login.do")
                .failureUrl("/login.jsp?authentication_error=true")
                .usernameParameter("j_username")
                .passwordParameter("j_password")
                .permitAll();
    }
}

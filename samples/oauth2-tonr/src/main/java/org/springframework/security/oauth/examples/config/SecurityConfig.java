package org.springframework.security.oauth.examples.config;

import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*;
import static org.springframework.security.config.annotation.web.WebSecurityConfigurators.*;
import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder;
import org.springframework.security.config.annotation.web.DefaultSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder;
import org.springframework.security.config.annotation.web.FilterChainProxySecurityBuilder;
import org.springframework.security.config.annotation.web.FormLoginSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.LogoutFilterSecurityBuilder;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.access.ExceptionTranslationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationMgr() throws Exception {
        return authenticationManager(userDetailsManager()).build();
    }

    @Bean
    public InMemoryUserDetailsManagerSecurityBuilder userDetailsManager() throws Exception {
        return inMemoryAuthentication(
          user("marissa").password("wombat").roles("USER"),
          user("sam").password("kangaroo").roles("USER"));
    }

    @Bean
    public FilterChainProxySecurityBuilder builder(OAuth2ClientContextFilter oauth2ClientFilter) throws Exception {
        ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder fiSourceBldr = interceptUrls()
            .hasRole(antMatchers("/sparklr/**","/facebook/**"), "USER")
            .permitAll(antMatchers("/**"));

        return new FilterChainProxySecurityBuilder()
            .ignoring(antMatchers("/resources/**"))
            .securityFilterChains(
                new SecurityFilterChainSecurityBuilder(authenticationMgr())
                    .apply(new DefaultSecurityFilterConfigurator(fiSourceBldr)
                        .withLogout(new LogoutFilterSecurityBuilder()
                            .logoutSuccessUrl("/login.jsp")
                            .logoutUrl("/logout.do"))
                        .permitAll())
                    .apply(new FormLoginSecurityFilterConfigurator()
                        .loginPage("/login.jsp")
                        .loginProcessingUrl("/login.do")
                        .failureUrl("/login.jsp?authentication_error=true")
                        .usernameParameter("j_username")
                        .passwordParameter("j_password")
                        .permitAll())
                    .addFilterAfter(oauth2ClientFilter, ExceptionTranslationFilter.class)
                 );
    }

}

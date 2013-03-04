package org.springframework.security.oauth.examples.config;

import static org.springframework.security.config.annotation.SecurityExpressions.hasRole;
import static org.springframework.security.config.annotation.SecurityExpressions.permitAll;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.authenticationManager;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.inMemoryAuthentication;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.user;
import static org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder.antMatchers;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder;
import org.springframework.security.config.annotation.web.DefaultSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.FilterChainProxySecurityBuilder;
import org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder;
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
        FilterInvocationSecurityMetadataSourceSecurityBuilder fiSourceBldr = new FilterInvocationSecurityMetadataSourceSecurityBuilder()
            .interceptUrl(antMatchers("/sparklr/**","/facebook/**"), hasRole("USER"))
            .antInterceptUrl("/**", permitAll);

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

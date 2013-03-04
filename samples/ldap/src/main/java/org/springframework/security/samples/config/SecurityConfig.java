package org.springframework.security.samples.config;

import static org.springframework.security.config.annotation.SecurityExpressions.hasRole;
import static org.springframework.security.config.annotation.SecurityExpressions.permitAll;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.authenticationManager;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.ldapAuthenticationProvider;
import static org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder.antMatchers;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.DefaultSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.FilterChainProxySecurityBuilder;
import org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder;
import org.springframework.security.config.annotation.web.FormLoginSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity
public class SecurityConfig {
    private String userDn = "uid=admin,ou=system";

    private String password = "secret";

    @Bean
    public AuthenticationManager authenticationMgr() throws Exception {
        return authenticationManager(ldapAuthenticationProvider(contextSource()).userDnPatterns("uid={0},ou=people").groupSearchFilter("(member={0})")).build();
    }

    @Bean
    public BaseLdapPathContextSource contextSource() throws Exception {
        DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
                "ldap://127.0.0.1:33389/dc=springframework,dc=org");
        contextSource.setUserDn(userDn);
        contextSource.setPassword(password);
        contextSource.afterPropertiesSet();
        return contextSource;
    }

    @Bean
    public ApacheDSContainer ldapServer() throws Exception {
        ApacheDSContainer apacheDSContainer = new ApacheDSContainer("dc=springframework,dc=org", "classpath:/users.ldif");
        apacheDSContainer.setPort(33389);
        return apacheDSContainer;
    }


    @Bean
    public FilterChainProxySecurityBuilder builder() throws Exception {
        FilterInvocationSecurityMetadataSourceSecurityBuilder fiSourceBldr = new FilterInvocationSecurityMetadataSourceSecurityBuilder()
            // TODO type safe configAttributes
            .interceptUrl(antMatchers("/users**","/sessions/**"), hasRole("ADMIN"))
            .interceptUrl(antMatchers("/resources/**","/signup"), permitAll)
            .antInterceptUrl("/**", hasRole("USER"));

        return new FilterChainProxySecurityBuilder()
            .ignoring(antMatchers("/resources/**"))
            .securityFilterChains(
                new SecurityFilterChainSecurityBuilder(authenticationMgr())
                    .apply(new DefaultSecurityFilterConfigurator(fiSourceBldr).permitAll())
                    .apply(new FormLoginSecurityFilterConfigurator().permitAll()));
    }
}

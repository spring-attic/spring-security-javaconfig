package org.springframework.security.samples.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizations;
import org.springframework.security.config.annotation.web.HttpConfiguration;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapater;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapater {
    private String userDn = "uid=admin,ou=system";

    private String password = "secret";

    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
        ignoredRequests
            .antMatchers("/resources/**");
    }

    protected AuthenticationManager authenticationManager(
            AuthenticationBuilder authenticationRegistry) throws Exception {
        return authenticationRegistry
            .ldapAuthenticationProvider(contextSource())
                .userDnPatterns("uid={0},ou=people")
                .groupSearchFilter("(member={0})")
                .and()
            .build();
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizations interceptUrls) {
        interceptUrls
            .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
            .antMatchers("/resources/**","/signup").permitAll()
            .antMatchers("/**").hasRole("USER");
    }

    protected void configure(HttpConfiguration http) throws Exception {
        http
            .formLogin()
            .permitAll();
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
}

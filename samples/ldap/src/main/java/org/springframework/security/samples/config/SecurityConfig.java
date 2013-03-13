package org.springframework.security.samples.config;

import static org.springframework.security.config.annotation.web.util.RequestMatchers.antMatchers;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizationRegistry;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;
import org.springframework.security.config.annotation.web.SimpleWebSecurityConfig;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.security.web.util.RequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends SimpleWebSecurityConfig {
    private String userDn = "uid=admin,ou=system";

    private String password = "secret";

    protected List<RequestMatcher> ignoredRequests() {
        return antMatchers("/resources/**");
    }

    protected void registerAuthentication(
            AuthenticationRegistry authenticationRegistry) throws Exception {
        authenticationRegistry
            .ldapAuthenticationProvider(contextSource())
                .userDnPatterns("uid={0},ou=people")
                .groupSearchFilter("(member={0})");
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizationRegistry interceptUrls) {
        interceptUrls
            .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
            .antMatchers("/resources/**","/signup").permitAll()
            .antMatchers("/**").hasRole("USER");
    }

    protected void configure(
            SecurityFilterChainSecurityBuilder springSecurityFilterChain) throws Exception {
        springSecurityFilterChain
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

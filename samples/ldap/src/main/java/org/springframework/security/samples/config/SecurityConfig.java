package org.springframework.security.samples.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.HttpConfigurator;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private String userDn = "uid=admin,ou=system";

    private String password = "secret";

    @Override
    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
        ignoredRequests
            .antMatchers("/resources/**");
    }

    @Override
    protected void registerAuthentication(
            AuthenticationRegistry builder) throws Exception {
        builder
            .ldapAuthenticationProvider()
                .contextSource(contextSource())
                .userDnPatterns("uid={0},ou=people")
                .groupSearchFilter("(member={0})");
    }

    @Override
    protected void configure(HttpConfigurator http) throws Exception {
        http
            .authorizeUrls()
                .antMatchers("/users**","/sessions/**").hasRole("ADMIN")
                .antMatchers("/resources/**","/signup").permitAll()
                .antMatchers("/**").hasRole("USER")
                .and()
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

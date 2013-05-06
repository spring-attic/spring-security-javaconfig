package org.springframework.security.oauth.examples.sparklr.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizations;
import org.springframework.security.config.annotation.web.HttpConfigurator;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Autowired
    private ClientDetailsUserDetailsService clientDetailsService;

    @Autowired
    private ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter;

    @Autowired
    private OAuth2AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    private OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    private OAuth2AuthenticationProcessingFilter resourcesServerFilter;

    @Autowired
    private OAuth2WebSecurityExpressionHandler oauthWebExpressionHandler;

    @Bean
    public AuthenticationManager clientAuthenticationManager() throws Exception {
        return new AuthenticationBuilder()
            .userDetails(clientDetailsService)
                .and()
            .build();
    }

    @Bean(name = {"authManager",BeanIds.AUTHENTICATION_MANAGER})
    public AuthenticationManager authManager() throws Exception {
        return new AuthenticationBuilder()
            .inMemoryAuthentication()
                .withUser("marissa").password("koala").roles("USER").and()
                .withUser("paul").password("emu").roles("USER").and()
                .and()
            .build();
    }

    @Configuration
    @Order(1)
    public static class OAuthTokenSecurityConfig extends WebSecurityConfigurerAdapter {
        @Autowired
        private SecurityConfiguration securityConfig;

        protected AuthenticationManager authenticationManager() throws Exception {
            return securityConfig.clientAuthenticationManager();
        }

        protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
            ignoredRequests
                .antMatchers("/oauth/cache_approvals","/oauth/uncache_approvals");
        }

        protected void authorizeUrls(
                ExpressionUrlAuthorizations interceptUrls) {
            interceptUrls
                .expressionHandler(securityConfig.oauthWebExpressionHandler)
                .antMatchers("/oauth/token").fullyAuthenticated()

                .regexMatchers(HttpMethod.DELETE, "/oauth/users/([^/].*?)/tokens/.*")
                    .access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('write')")
                .regexMatchers(HttpMethod.GET, "/oauth/users/.*")
                    .access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('read')")
                .regexMatchers(HttpMethod.GET, "/oauth/clients/.*")
                    .access("#oauth2.clientHasRole('ROLE_CLIENT') and #oauth2.isClient() and #oauth2.hasScope('read')")

                .antMatchers("/photos").hasAnyAuthority("ROLE_USER","SCOPE_TRUST")
                .antMatchers("/photos/trusted/**").hasAnyAuthority("ROLE_CLIENT","SCOPE_TRUST")
                .antMatchers("/photos/user/**").hasAnyAuthority("ROLE_USER","SCOPE_TRUST")
                .antMatchers("/photos/**").hasAnyAuthority("ROLE_USER","SCOPE_READ");
        }

        protected void configure(HttpConfigurator http) throws Exception {
            http
                .regexMatcher("(photos/.*|/oauth/(token|clients/.*|users/.*))")
                .authenticationEntryPoint(securityConfig.oauthAuthenticationEntryPoint)
                    .applyDefaultConfigurators()
                    .exceptionHandling()
                        .accessDeniedHandler(securityConfig.oauthAccessDeniedHandler)
                        .and()
                    .logout()
                        .and()
                    .httpBasic()
                        .authenticationEntryPoint(securityConfig.oauthAuthenticationEntryPoint)
                        .and()
                    .addFilterBefore(securityConfig.resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterBefore(securityConfig.clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class);
        }
    }

    @Configuration
    public static class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
        @Autowired
        private SecurityConfiguration securityConfig;

        protected AuthenticationManager authenticationManager() throws Exception {
            return securityConfig.authManager();
        }

        protected void authorizeUrls(
                ExpressionUrlAuthorizations interceptUrls) {
            interceptUrls
                .antMatchers("/oauth/**").hasRole("USER")
                .antMatchers("/**").permitAll();
        }

        protected void configure(HttpConfigurator http) throws Exception {
            http
                .authenticationEntryPoint(securityConfig.oauthAuthenticationEntryPoint)
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
                        .loginProcessingUrl("/login.do")
                        .and()
                .addFilterBefore(securityConfig.resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class);
        }
    }
}

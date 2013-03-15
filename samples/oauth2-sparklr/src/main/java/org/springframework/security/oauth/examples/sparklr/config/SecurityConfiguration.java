package org.springframework.security.oauth.examples.sparklr.config;

import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.FilterChainProxySecurityBuilder;
import org.springframework.security.config.annotation.web.SecurityFilterChainSecurityBuilder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RegexRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Autowired
    private ClientDetailsUserDetailsService clientDetailsService;

    @Bean
    public AuthenticationManager clientAuthenticationManager() throws Exception {
        return new AuthenticationRegistry()
            .userDetails(clientDetailsService)
            .and()
        .build();
    }

    @Bean(name = {"authManager",BeanIds.AUTHENTICATION_MANAGER})
    public AuthenticationManager authManager() throws Exception {
        return new AuthenticationRegistry()
            .inMemoryAuthentication()
                .withUser("marissa").password("koala").roles("USER").and()
                .withUser("paul").password("emu").roles("USER").and()
            .and()
        .build();
    }

    @Bean
    public FilterChainProxySecurityBuilder builder(ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter,
            OAuth2AccessDeniedHandler oauthAccessDeniedHandler,
            OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint,
            OAuth2AuthenticationProcessingFilter resourcesServerFilter,
            OAuth2WebSecurityExpressionHandler oauthWebExpressionHandler) throws Exception {

        return new FilterChainProxySecurityBuilder()
            .ignoring(antMatchers("/oauth/cache_approvals","/oauth/uncache_approvals"))
            .securityFilterChains(
                new SecurityFilterChainSecurityBuilder(clientAuthenticationManager())
                    .requestMatcher(new AntPathRequestMatcher("/oauth/token"))
                    .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                    .applyDefaultConfigurators()
                    .exceptionHandling()
                        .accessDeniedHandler(oauthAccessDeniedHandler)
                        .and()
                    .logout()
                        .and()
                    .httpBasic()
                        .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                        .and()
                    .addFilterBefore(clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class)
                    .authorizeUrls()
                        .antMatchers("/oauth/token").fullyAuthenticated()
                        .and(),

                new SecurityFilterChainSecurityBuilder(clientAuthenticationManager())
                    .requestMatcher(new RegexRequestMatcher("/oauth/(users|clients)/.*",null))
                    .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                    .applyDefaultConfigurators()
                    .exceptionHandling()
                        .accessDeniedHandler(oauthAccessDeniedHandler)
                        .and()
                    .logout()
                        .and()
                    .addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
                    .authorizeUrls()
                        .expressionHandler(oauthWebExpressionHandler)
                        .regexMatchers(HttpMethod.DELETE, "/oauth/users/([^/].*?)/tokens/.*").configAttribute("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('write')")
                        .regexMatchers(HttpMethod.GET, "/oauth/users/.*").configAttribute("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('read')")
                        .regexMatchers(HttpMethod.GET, "/oauth/clients/.*").configAttribute("#oauth2.clientHasRole('ROLE_CLIENT') and #oauth2.isClient() and #oauth2.hasScope('read')")
                        .and(),

                new SecurityFilterChainSecurityBuilder(authManager())
                    .requestMatcher(new AntPathRequestMatcher("/photos/**"))
                    .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                    .applyDefaultConfigurators()
                    .exceptionHandling()
                        .accessDeniedHandler(oauthAccessDeniedHandler)
                        .and()
                    .logout()
                        .and()
                    .addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
                    .authorizeUrls()
                        .antMatchers("/photos").hasAnyAuthority("ROLE_USER","SCOPE_TRUST")
                        .antMatchers("/photos/trusted/**").hasAnyAuthority("ROLE_CLIENT","SCOPE_TRUST")
                        .antMatchers("/photos/user/**").hasAnyAuthority("ROLE_USER","SCOPE_TRUST")
                        .antMatchers("/photos/**").hasAnyAuthority("ROLE_USER","SCOPE_READ")
                        .and(),

                new SecurityFilterChainSecurityBuilder(authManager())
                    .authenticationEntryPoint(oauthAuthenticationEntryPoint)
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
                    .addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
                    .authorizeUrls()
                        .antMatchers("/oauth/**").hasRole("USER")
                        .antMatchers("/**").permitAll()
                        .and()
            );
    }
}

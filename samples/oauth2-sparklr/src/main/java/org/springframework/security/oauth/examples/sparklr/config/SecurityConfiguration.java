package org.springframework.security.oauth.examples.sparklr.config;

import static org.springframework.security.config.annotation.SecurityExpressions.*;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.authenticationManager;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.authenticationProvider;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.inMemoryAuthentication;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.user;
import static org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder.antMatchers;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.web.HttpBasicSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.DefaultSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.EnableWebSecurity;
import org.springframework.security.config.annotation.web.FilterChainProxySecurityBuilder;
import org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder;
import org.springframework.security.config.annotation.web.FormLoginSecurityFilterConfigurator;
import org.springframework.security.config.annotation.web.LogoutFilterSecurityBuilder;
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
        return authenticationManager(authenticationProvider(clientDetailsService)).build();
    }

    @Bean(name = {"authManager",BeanIds.AUTHENTICATION_MANAGER})
    public AuthenticationManager authManager() throws Exception {
        return authenticationManager(
            inMemoryAuthentication(
                user("marissa").password("koala").roles("USER"),
                user("paul").password("emu").roles("USER")
            )
        ).build();
    }

    @Bean
    public FilterChainProxySecurityBuilder builder(ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter,
            OAuth2AccessDeniedHandler oauthAccessDeniedHandler,
            OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint,
            OAuth2AuthenticationProcessingFilter resourcesServerFilter,
            OAuth2WebSecurityExpressionHandler oauthWebExpressionHandler) throws Exception {
        FilterInvocationSecurityMetadataSourceSecurityBuilder tokenFiMetadataSourceBldr = new FilterInvocationSecurityMetadataSourceSecurityBuilder()
            .interceptUrl(antMatchers("/oauth/token"), fullyAuthenticated);
        FilterInvocationSecurityMetadataSourceSecurityBuilder userClientFiMetadataSourceBldr = new FilterInvocationSecurityMetadataSourceSecurityBuilder()
            .interceptUrl(new RegexRequestMatcher("/oauth/users/([^/].*?)/tokens/.*", "DELETE"), "#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('write')")
            .interceptUrl(new RegexRequestMatcher("/oauth/users/.*", "GET"),"#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('read')")
            .interceptUrl(new RegexRequestMatcher("/oauth/clients/.*", "GET"),"#oauth2.clientHasRole('ROLE_CLIENT') and #oauth2.isClient() and #oauth2.hasScope('read')")
            .expressionHandler(oauthWebExpressionHandler);
        FilterInvocationSecurityMetadataSourceSecurityBuilder photoFiMetadataSourceBldr = new FilterInvocationSecurityMetadataSourceSecurityBuilder()
            .interceptUrl(antMatchers("/photos"), hasAnyAuthority("ROLE_USER","SCOPE_TRUST"))
            .interceptUrl(antMatchers("/photos/trusted/**"), hasAnyAuthority("ROLE_CLIENT","SCOPE_TRUST"))
            .interceptUrl(antMatchers("/photos/user/**"), hasAnyAuthority("ROLE_USER","SCOPE_TRUST"))
            .interceptUrl(antMatchers("/photos/**"), hasAnyAuthority("ROLE_USER","SCOPE_READ"));
        FilterInvocationSecurityMetadataSourceSecurityBuilder fiMetadataSourceBldr = new FilterInvocationSecurityMetadataSourceSecurityBuilder()
            .interceptUrl(antMatchers("/oauth/**"), hasRole("USER"))
            .interceptUrl(antMatchers("/**"), permitAll);

        return new FilterChainProxySecurityBuilder()
            .ignoring(antMatchers("/oauth/cache_approvals","/oauth/uncache_approvals"))
            .securityFilterChains(
                new SecurityFilterChainSecurityBuilder(clientAuthenticationManager())
                    .requestMatcher(new AntPathRequestMatcher("/oauth/token"))
                    .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                    .apply(new DefaultSecurityFilterConfigurator(tokenFiMetadataSourceBldr)
                            .accessDeniedHandler(oauthAccessDeniedHandler)
                            .disableAnonymous(true))
                    .apply(new HttpBasicSecurityFilterConfigurator()
                            .authenticationEntryPoint(oauthAuthenticationEntryPoint))
                    .addFilterBefore(clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class),

                new SecurityFilterChainSecurityBuilder(clientAuthenticationManager())
                    .requestMatcher(new RegexRequestMatcher("/oauth/(users|clients)/.*",null))
                    .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                    .apply(new DefaultSecurityFilterConfigurator(userClientFiMetadataSourceBldr)
                            .accessDeniedHandler(oauthAccessDeniedHandler)
                            .disableAnonymous(true))
                    .addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class),

                new SecurityFilterChainSecurityBuilder(authManager())
                    .requestMatcher(new AntPathRequestMatcher("/photos/**"))
                    .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                    .apply(new DefaultSecurityFilterConfigurator(photoFiMetadataSourceBldr)
                            .accessDeniedHandler(oauthAccessDeniedHandler)
                            .disableAnonymous(true))
                    .addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class),

                new SecurityFilterChainSecurityBuilder(authManager())
                    .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                    .apply(new DefaultSecurityFilterConfigurator(fiMetadataSourceBldr)
                            .accessDeniedPage("/login.jsp?authorization_error=true")
                            .withLogout(new LogoutFilterSecurityBuilder()
                                .logoutSuccessUrl("/index.jsp")
                                .logoutUrl("/logout.do"))
                            )
                    .apply(new FormLoginSecurityFilterConfigurator()
                            .usernameParameter("j_username")
                            .passwordParameter("j_password")
                            .failureUrl("/login.jsp?authentication_error=true")
                            .loginPage("/login.jsp")
                            .loginProcessingUrl("/login.do"))
                    .addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
            );
    }
}

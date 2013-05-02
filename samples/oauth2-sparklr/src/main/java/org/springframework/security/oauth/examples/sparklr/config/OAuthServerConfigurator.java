/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth.examples.sparklr.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.oauth.examples.sparklr.oauth.SparklrUserApprovalHandler;
import org.springframework.security.oauth2.provider.AuthorizationRequestManager;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequestManager;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.endpoint.WhitelabelApprovalEndpoint;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.vote.ScopeVoter;

/**
 * @author Rob Winch
 *
 */
@Configuration
@Order(-500)
public class OAuthServerConfigurator implements WebSecurityConfigurer {
    @Autowired
    private SecurityConfiguration securityConfig;

    public void init(WebSecurityConfiguration builder) throws Exception {

    }

    public void configure(WebSecurityConfiguration builder) throws Exception {
    }

    @Bean
    public OAuth2AuthenticationEntryPoint oauthEntryPoint() {
        OAuth2AuthenticationEntryPoint oauthEntryPoint = new OAuth2AuthenticationEntryPoint();
        oauthEntryPoint.setRealmName("OAuth Realm"); // FIXME allow customization of the realm
        return oauthEntryPoint;
    }

    @Bean
    public OAuth2AccessDeniedHandler oauthAcccessDeniedHandler() {
        return new OAuth2AccessDeniedHandler();
    }

    @Bean
    public ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter() throws Exception {
        ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter = new ClientCredentialsTokenEndpointFilter();
        clientCredentialsTokenEndpointFilter.setAuthenticationManager(authenticationManager());
        return clientCredentialsTokenEndpointFilter;
    }

    @Bean
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter> voters = new ArrayList<AccessDecisionVoter>();
        voters.add(new ScopeVoter());
        voters.add(new RoleVoter());
        voters.add(new AuthenticatedVoter());
        return new UnanimousBased(voters);
    }

    @Bean
    public AuthorizationEndpoint authorizationEndpoint() throws Exception {
        AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint();
        authorizationEndpoint.setTokenGranter(tokenGranter());
        authorizationEndpoint.setClientDetailsService(clientDetails());
        authorizationEndpoint.setAuthorizationCodeServices(authorizationCodeServices());
        return authorizationEndpoint;
    }

    @Bean
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(clientDetails());
        return tokenServices;
    }

    @Bean
    public TokenEndpoint tokenEndpoint() throws Exception {
        TokenEndpoint tokenEndpoint = new TokenEndpoint();
        tokenEndpoint.setClientDetailsService(clientDetails());
        tokenEndpoint.setTokenGranter(tokenGranter());
        return tokenEndpoint;
    }

    @Bean
    public AuthorizationCodeTokenGranter authorizationTokenGranter() {
        return new AuthorizationCodeTokenGranter(tokenServices(), authorizationCodeServices(), clientDetails());
    }

    @Bean
    public AuthorizationRequestManager authorizationRequestManager() {
        return new DefaultAuthorizationRequestManager(clientDetails());
    }

    @Bean
    public InMemoryAuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }

    @Bean
    public WhitelabelApprovalEndpoint approvalEndpoint() {
        return new WhitelabelApprovalEndpoint ();
    }


    @Bean
    public ClientDetailsUserDetailsService clientDetailsUserService() {
        return new ClientDetailsUserDetailsService(clientDetails());
    }

    @Bean
    public InMemoryTokenStore tokenStore() {
        return new InMemoryTokenStore();
    }

    @Bean
    public TokenGranter tokenGranter() throws Exception {
        List<TokenGranter> tokenGranters = new ArrayList<TokenGranter>();
        tokenGranters.add(new AuthorizationCodeTokenGranter(tokenServices(),authorizationCodeServices(),clientDetails()));
        tokenGranters.add(new RefreshTokenGranter(tokenServices(), clientDetails()));
        tokenGranters.add(new ImplicitTokenGranter(tokenServices(), clientDetails()));
        tokenGranters.add(new ClientCredentialsTokenGranter(tokenServices(), clientDetails()));
        tokenGranters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager(), tokenServices(), clientDetails()));
        return new CompositeTokenGranter(tokenGranters);
    }

    @Bean
    public FrameworkEndpointHandlerMapping endpointHandlerMapping() {
        FrameworkEndpointHandlerMapping mapping = new FrameworkEndpointHandlerMapping();

        return mapping;
    }

    @Bean
    public SparklrUserApprovalHandler userApprovalHandler() {
        SparklrUserApprovalHandler handler = new SparklrUserApprovalHandler();
        handler.setTokenServices(tokenServices());
        handler.setAutoApproveClients(Collections.singleton("my-less-trusted-autoapprove-client"));
        return handler;
    }

    @Bean
    public ClientDetailsService clientDetails() {
        return new ClientDetailsServiceBuilder()
            .withClient("my-trusted-client")
                .authorizedGrantTypes("password","authorization_code","refresh_token","implicit")
                .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
                .scopes("read","write","trust")
                .accessTokenValiditySeconds(60)
                .and()
            .withClient("my-trusted-client-with-secret")
                .authorizedGrantTypes("password","authorization_code","refresh_token","implicit")
                .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
                .scopes("read","write","trust")
                .secret("somesecret")
                .and()
            .withClient("my-client-with-secret")
                .authorizedGrantTypes("client_credentials")
                .authorities("ROLE_CLIENT")
                .scopes("read")
                .secret("secret")
                .and()
            .withClient("my-less-trusted-client")
                .authorizedGrantTypes("authorization_code","implicit")
                .authorities("ROLE_CLIENT")
                .scopes("read")
                .secret("secret")
                .and()
            .withClient("my-less-trusted-autoapprove-client")
                .authorizedGrantTypes("implicit")
                .authorities("ROLE_CLIENT")
                .scopes("read")
                .secret("secret")
                .and()
            .withClient("my-client-with-registered-redirect")
                .authorizedGrantTypes("authorization_code","client_credentials")
                .authorities("ROLE_CLIENT")
                .scopes("read","trust")
                .redirectUris("http://anywhere?key=value")
                .and()
            .withClient("my-untrusted-client-with-registered-redirect")
                .authorizedGrantTypes("authorization_code")
                .authorities("ROLE_CLIENT")
                .scopes("read")
                .redirectUris("http://anywhere")
                .and()
            .withClient("tonr")
                .resourceIds("sparklr")
                .authorizedGrantTypes("authorization_code","implicit")
                .authorities("ROLE_CLIENT")
                .scopes("read","write")
                .secret("secret")
                .and()
            .build();
    }

    @Bean
    public OAuth2AuthenticationProcessingFilter oauthAuthenticationProcessingFilter() {
        OAuth2AuthenticationProcessingFilter oauthAuthFilter = new OAuth2AuthenticationProcessingFilter();
        oauthAuthFilter.setAuthenticationManager(oauthAuthenticationManager());
        return oauthAuthFilter;
    }

    /**
     * @return
     */
    @Bean
    public AuthenticationManager oauthAuthenticationManager() {
        OAuth2AuthenticationManager oauthAuthenticationManager = new OAuth2AuthenticationManager();
        oauthAuthenticationManager.setResourceId("sparklr");
        oauthAuthenticationManager.setTokenServices(tokenServices());
        return oauthAuthenticationManager;
    }

    @Bean
    public OAuth2WebSecurityExpressionHandler oauthWebExpressionHandler() {
        return new OAuth2WebSecurityExpressionHandler();
    }

    /**
     * @return
     * @throws Exception
     */
    protected AuthenticationManager authenticationManager() throws Exception {
        return securityConfig.clientAuthenticationManager();
    }
}

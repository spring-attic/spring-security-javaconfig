/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.oauth2.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class OAuth2ServerConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
    private AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();

    private ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter;
    private OAuth2AuthenticationProcessingFilter resourcesServerFilter;
    private AuthorizationServerTokenServices tokenServices;
    private AuthorizationCodeServices authorizationCodeServices;
    private ResourceServerTokenServices resourceTokenServices;
    private TokenStore tokenStore;
    private TokenGranter tokenGranter;
    private ConsumerTokenServices consumerTokenServices;
    private String resourceId = "oauth2-resource";
    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new OAuth2WebSecurityExpressionHandler();

    private ClientDetailsService clientDetails() {
        return getBuilder().getSharedObject(ClientDetailsService.class);
    }

    public AuthorizationServerTokenServices getTokenServices() {
        return tokenServices;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        if(http.getConfigurer(HttpBasicConfigurer.class) == null) {
            http.httpBasic();
        }

        http.setSharedObject(AuthenticationEntryPoint.class, authenticationEntryPoint);
    }

    public OAuth2ServerConfigurer resourceId(String resourceId) {
        this.resourceId = resourceId;
        return this;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void configure(HttpSecurity http) throws Exception {

        http.getConfigurer(ExpressionUrlAuthorizationConfigurer.class).expressionHandler(expressionHandler);

        clientCredentialsTokenEndpointFilter = new ClientCredentialsTokenEndpointFilter();
        clientCredentialsTokenEndpointFilter.setAuthenticationManager(http
                .getAuthenticationManager());
        clientCredentialsTokenEndpointFilter = postProcess(clientCredentialsTokenEndpointFilter);

        AuthenticationManager oauthAuthenticationManager = oauthAuthenticationManager(http);
        resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
        resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager);
        resourcesServerFilter = postProcess(resourcesServerFilter);

        this.tokenGranter = tokenGranter(http);
        this.consumerTokenServices = consumerTokenServices(http);

        http.
            getConfigurer(ExceptionHandlingConfigurer.class)
                .accessDeniedHandler(accessDeniedHandler);

        http
            .addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
            .addFilterBefore(clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class);

    }

    private AuthenticationManager oauthAuthenticationManager(HttpSecurity http) {
        OAuth2AuthenticationManager oauthAuthenticationManager = new OAuth2AuthenticationManager();
        oauthAuthenticationManager.setResourceId(resourceId);
        oauthAuthenticationManager
                .setTokenServices(resourceTokenServices(http));
        return oauthAuthenticationManager;
    }

    private ResourceServerTokenServices resourceTokenServices(
            HttpSecurity http) {
        tokenServices(http);
        return this.resourceTokenServices;
    }

    private AuthorizationServerTokenServices tokenServices(HttpSecurity http) {
        if (tokenServices != null) {
            return tokenServices;
        }
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(clientDetails());
        this.tokenServices = tokenServices;
        this.resourceTokenServices = tokenServices;
        return tokenServices;
    }

    private TokenStore tokenStore() {
        if (tokenStore == null) {
            this.tokenStore = new InMemoryTokenStore();
        }
        return this.tokenStore;
    }

    public AuthorizationCodeServices getAuthorizationCodeServices() {
        return authorizationCodeServices;
    }

    private AuthorizationCodeServices authorizationCodeServices(
            HttpSecurity http) {
        if (authorizationCodeServices == null) {
            authorizationCodeServices = new InMemoryAuthorizationCodeServices();
        }
        return authorizationCodeServices;
    }

    private AuthenticationManager authenticationManager(HttpSecurity http) {
        return http.getAuthenticationManager();
    }

    public TokenGranter getTokenGranter() {
        return tokenGranter;
    }

    public ConsumerTokenServices getConsumerTokenServices() {
        return consumerTokenServices;
    }

    private ConsumerTokenServices consumerTokenServices(HttpSecurity http) {
        if(consumerTokenServices == null) {
            DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
            defaultTokenServices.setClientDetailsService(clientDetails());
            defaultTokenServices.setTokenStore(tokenStore());
            consumerTokenServices = defaultTokenServices;
        }
        return consumerTokenServices;
    }

    private TokenGranter tokenGranter(HttpSecurity http) throws Exception {
        if(tokenGranter == null) {
            ClientDetailsService clientDetails = clientDetails();
            AuthorizationServerTokenServices tokenServices = tokenServices(http);
            AuthorizationCodeServices authorizationCodeServices = authorizationCodeServices(http);
            AuthenticationManager authenticationManager = authenticationManager(http);

            List<TokenGranter> tokenGranters = new ArrayList<TokenGranter>();
            tokenGranters.add(new AuthorizationCodeTokenGranter(tokenServices,
                    authorizationCodeServices, clientDetails));
            tokenGranters
                    .add(new RefreshTokenGranter(tokenServices, clientDetails));
            tokenGranters
                    .add(new ImplicitTokenGranter(tokenServices, clientDetails));
            tokenGranters.add(new ClientCredentialsTokenGranter(tokenServices,
                    clientDetails));
            tokenGranters.add(new ResourceOwnerPasswordTokenGranter(
                    authenticationManager, tokenServices, clientDetails));
            tokenGranter = new CompositeTokenGranter(tokenGranters);
        }
        return tokenGranter;
    }
}

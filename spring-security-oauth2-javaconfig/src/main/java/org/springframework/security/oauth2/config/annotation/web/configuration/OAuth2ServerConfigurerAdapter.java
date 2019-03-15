/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.config.annotation.web.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2ServerConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.endpoint.WhitelabelApprovalEndpoint;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;

/**
 * @author Rob Winch
 *
 */
@Configuration
public abstract class OAuth2ServerConfigurerAdapter extends WebSecurityConfigurerAdapter {
    @Bean
    public AuthorizationEndpoint authorizationEndpoint() throws Exception {
        AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint();
        authorizationEndpoint.setTokenGranter(tokenGranter());
        authorizationEndpoint.setClientDetailsService(clientDetails());
        authorizationEndpoint.setAuthorizationCodeServices(authorizationCodeServices());
        return authorizationEndpoint;
    }

    @Bean
    public ConsumerTokenServices consumerTokenServices() throws Exception {
        return oauthConfigurer().getConsumerTokenServices();
    }

    /**
     * @return
     */
    private AuthorizationCodeServices authorizationCodeServices() throws Exception {
        return oauthConfigurer().getAuthorizationCodeServices();
    }

    /**
     * @return
     */
    private TokenGranter tokenGranter() throws Exception {
        return oauthConfigurer().getTokenGranter();
    }

    private OAuth2ServerConfigurer oauthConfigurer() throws Exception {
        return getHttp().getConfigurer(OAuth2ServerConfigurer.class);
    }

    @Bean
    public TokenEndpoint tokenEndpoint() throws Exception {
        TokenEndpoint tokenEndpoint = new TokenEndpoint();
        tokenEndpoint.setClientDetailsService(clientDetails());
        tokenEndpoint.setTokenGranter(tokenGranter());
        return tokenEndpoint;
    }

    @Bean
    public AuthorizationCodeTokenGranter authorizationTokenGranter() throws Exception {
        return new AuthorizationCodeTokenGranter(tokenServices(), authorizationCodeServices(), clientDetails());
    }

    /**
     * @return
     * @throws Exception
     */
    protected AuthorizationServerTokenServices tokenServices() throws Exception {
        return oauthConfigurer().getTokenServices();
    }

    @Bean
    public WhitelabelApprovalEndpoint approvalEndpoint() {
        return new WhitelabelApprovalEndpoint ();
    }

    @Bean
    public FrameworkEndpointHandlerMapping endpointHandlerMapping() {
        return new FrameworkEndpointHandlerMapping();
    }

    @Bean
    public ClientDetailsService clientDetailsServiceBean() throws Exception {
        return clientDetails();
    }

    private ClientDetailsService clientDetails() throws Exception {
        return getHttp().getSharedObject(ClientDetailsService.class);
    }
}

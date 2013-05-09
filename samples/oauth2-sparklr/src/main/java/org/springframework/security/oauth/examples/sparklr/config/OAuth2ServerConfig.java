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

import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.ExpressionUrlAuthorizations;
import org.springframework.security.config.annotation.web.HttpConfigurator;
import org.springframework.security.config.annotation.web.OAuth2ServerConfigurator;
import org.springframework.security.config.annotation.web.OAuth2ServerConfigurerAdapter;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.oauth.examples.sparklr.oauth.SparklrUserApprovalHandler;
import org.springframework.security.oauth2.provider.ClientDetailsService;

/**
 * @author Rob Winch
 *
 */
@Configuration
@Order(1)
public class OAuth2ServerConfig extends OAuth2ServerConfigurerAdapter {
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
    @DependsOn("springSecurityFilterChain") // FIXME remove the need for @DependsOn
    public SparklrUserApprovalHandler userApprovalHandler() throws Exception {
        SparklrUserApprovalHandler handler = new SparklrUserApprovalHandler();
        handler.setTokenServices(tokenServices());
        handler.setAutoApproveClients(Collections.singleton("my-less-trusted-autoapprove-client"));
        return handler;
    }

    protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
        ignoredRequests
            .antMatchers("/oauth/cache_approvals","/oauth/uncache_approvals");
    }

    protected void authorizeUrls(
            ExpressionUrlAuthorizations interceptUrls) {
        interceptUrls
            .expressionHandler(oauthWebExpressionHandler()) // FIXME ideally this would be populated by the OAuth2Configurator
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
            .requestMatchers()
                .antMatchers("/photos/**","/oauth/token","/oauth/clients/**","/oauth/users/**")
            .apply(new OAuth2ServerConfigurator())
                .clientDetails(clientDetails());
    }
}

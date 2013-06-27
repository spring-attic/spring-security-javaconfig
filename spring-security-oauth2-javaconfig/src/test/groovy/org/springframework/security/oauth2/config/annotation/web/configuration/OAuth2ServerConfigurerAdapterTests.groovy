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
package org.springframework.security.oauth2.config.annotation.web.configuration;

import static org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2ServerConfigurerAdapterTestsConfigs.*

import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter

/**
 * @author Rob Winch
 *
 */
class OAuth2ServerConfigurerAdapterTests extends BaseSpringSpec {

    def "InMemoryClientDetailsServiceConfigurer"() {
        when:
            loadConfig(InMemoryClientDetailsConfig)
        then: "in memory clientdetails is used"
            UserDetailsService uds = findAuthenticationProvider(DaoAuthenticationProvider).userDetailsService
            uds instanceof ClientDetailsUserDetailsService
            uds.clientDetailsService instanceof InMemoryClientDetailsService
        and: "defaults http basic"
            findFilter(BasicAuthenticationFilter)
        and: "ClientCredentialsTokenEndpointFilter"
            findFilter(ClientCredentialsTokenEndpointFilter).authenticationManager == authenticationManager
        and: "OAuth2AuthenticationProcessingFilter"
            findFilter(OAuth2AuthenticationProcessingFilter).authenticationManager instanceof OAuth2AuthenticationManager
    }


}

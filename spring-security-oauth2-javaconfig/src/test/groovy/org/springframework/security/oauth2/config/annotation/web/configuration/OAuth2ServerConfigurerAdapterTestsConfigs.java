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

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.authentication.configurers.InMemoryClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2ServerConfigurer;

/**
 * @author Rob Winch
 *
 */
public class OAuth2ServerConfigurerAdapterTestsConfigs {
    @Configuration
    @EnableWebSecurity
    static class InMemoryClientDetailsConfig extends OAuth2ServerConfigurerAdapter {
        static String APP_NAME = "app";

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .apply(new InMemoryClientDetailsServiceConfigurer())
                    .withClient("android-crm")
                        .resourceIds(APP_NAME)
                        .scopes("read","write")
                        .authorities("ROLE_USER")
                        .secret("123456")
                        .authorizedGrantTypes("authorization_code","implicit","password");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeUrls()
                    .anyRequest().hasRole("USER")
                    .and()
                .apply(new OAuth2ServerConfigurer())
                    .resourceId(APP_NAME);
        }
    }
}

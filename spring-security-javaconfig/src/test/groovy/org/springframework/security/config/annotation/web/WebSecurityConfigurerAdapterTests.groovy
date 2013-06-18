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
package org.springframework.security.config.annotation.web;

import static org.junit.Assert.*

import javax.sql.DataSource

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType
import org.springframework.ldap.core.support.BaseLdapPathContextSource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder
import org.springframework.security.ldap.DefaultSpringSecurityContextSource

/**
 * @author Rob Winch
 *
 */
class WebSecurityConfigurerAdapterTests extends BaseSpringSpec {

    def "MessageSources populated on AuthenticationProviders"() {
        when:
            loadConfig(MessageSourcesPopulatedConfig)
            List<AuthenticationProvider> providers = authenticationProviders()
        then:
            providers*.messages*.messageSource == [context,context,context,context]
    }


    @Configuration
    @EnableWebSecurity
    static class MessageSourcesPopulatedConfig extends WebSecurityConfigurerAdapter {
        @Override
        public void configure(WebSecurityBuilder builder)	throws Exception {
            builder
                .ignoring()
                    .antMatchers("/ignore1","/ignore2");
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .antMatcher("/role1/**")
                .authorizeUrls()
                    .anyRequest().hasRole("1");
        }

        @Bean
        public BaseLdapPathContextSource contextSource() throws Exception {
            DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
                    "ldap://127.0.0.1:33389/dc=springframework,dc=org")
            contextSource.userDn = "uid=admin,ou=system"
            contextSource.password = "secret"
            contextSource.afterPropertiesSet();
            return contextSource;
        }

        @Bean
        public DataSource dataSource() {
            EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
            return builder.setType(EmbeddedDatabaseType.HSQL).build();
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication().and()
                .jdbcUserDetailsManager()
                    .dataSource(dataSource())
                    .and()
                .ldapAuthenticationProvider()
                    .contextSource(contextSource())
        }
    }
}

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

import org.springframework.beans.factory.BeanCreationException
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.AnyRequestMatcher

/**
 * @author Rob Winch
 *
 */
class WebSecurityConfigurationTests extends BaseSpringSpec {

    def "WebSecurityConfigurators are sorted"() {
        when:
            loadConfig(SortedWebSecurityConfigurerAdaptersConfig);
            List<SecurityFilterChain> filterChains = context.getBean(FilterChainProxy).filterChains
        then:
            filterChains[0].requestMatcher.pattern == "/ignore1"
            filterChains[0].filters.empty
            filterChains[1].requestMatcher.pattern == "/ignore2"
            filterChains[1].filters.empty

            filterChains[2].requestMatcher.pattern == "/role1/**"
            filterChains[3].requestMatcher.pattern == "/role2/**"
            filterChains[4].requestMatcher.pattern == "/role3/**"
            filterChains[5].requestMatcher.class == AnyRequestMatcher
    }


    @Configuration
    @EnableWebSecurity
    static class SortedWebSecurityConfigurerAdaptersConfig {
        public AuthenticationManager authenticationManager() throws Exception {
            return new AuthenticationManagerBuilder()
                .inMemoryAuthentication()
                    .withUser("marissa").password("koala").roles("USER").and()
                    .withUser("paul").password("emu").roles("USER").and()
                    .and()
                .build();
        }

        @Configuration
        @Order(1)
        public static class WebConfigurer1 extends WebSecurityConfigurerAdapter {
            @Override
            public void configure(SpringSecurityFilterChainBuilder builder)	throws Exception {
                builder
                    .ignoring()
                        .antMatchers("/ignore1","/ignore2");
            }

            @Override
            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .antMatcher("/role1/**")
                    .authorizeUrls()
                        .antMatchers("/**").hasRole("1");
            }
        }

        @Configuration
        @Order(2)
        public static class WebConfigurer2 extends WebSecurityConfigurerAdapter {
            @Override
            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .antMatcher("/role2/**")
                        .authorizeUrls()
                            .antMatchers("/**").hasRole("2");
            }
        }

        @Configuration
        @Order(3)
        public static class WebConfigurer3 extends WebSecurityConfigurerAdapter {
            @Override
            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .antMatcher("/role3/**")
                    .authorizeUrls()
                        .antMatchers("/**").hasRole("3");
            }
        }

        @Configuration
        public static class WebConfigurer4 extends WebSecurityConfigurerAdapter {

            @Override
            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .authorizeUrls()
                        .antMatchers("/**").hasRole("4");
            }
        }
    }

    def "WebSecurityConfigurators fails with duplicate order"() {
        when:
            loadConfig(DuplicateOrderConfig);
        then:
            BeanCreationException e = thrown()
            e.message.contains "@Order on WebSecurityConfigurators must be unique"
    }


    @Configuration
    @EnableWebSecurity
    static class DuplicateOrderConfig {
        public AuthenticationManager authenticationManager() throws Exception {
            return new AuthenticationManagerBuilder()
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .and()
                .build();
        }

        @Configuration
        public static class WebConfigurer1 extends WebSecurityConfigurerAdapter {

            @Override
            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .antMatcher("/role1/**")
                    .authorizeUrls()
                        .antMatchers("/**").hasRole("1");
            }
        }

        @Configuration
        public static class WebConfigurer2 extends WebSecurityConfigurerAdapter {
            @Override
            protected void configure(HttpConfiguration http) throws Exception {
                http
                    .antMatcher("/role2/**")
                    .authorizeUrls()
                        .antMatchers("/**").hasRole("2");
            }
        }
    }

}

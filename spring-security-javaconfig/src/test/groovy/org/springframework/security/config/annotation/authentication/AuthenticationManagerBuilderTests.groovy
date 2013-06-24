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
package org.springframework.security.config.annotation.authentication

import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationEventPublisher
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.LifecycleManager
import org.springframework.security.config.annotation.web.EnableWebSecurity
import org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter

/**
 *
 * @author Rob Winch
 *
 */
class AuthenticationManagerBuilderTests extends BaseSpringSpec {
    def "add(AuthenticationProvider) does not perform registration"() {
        setup:
            LifecycleManager lm = Mock()
            AuthenticationProvider provider = Mock()
            AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder().lifecycleManager(lm)
        when: "Adding an AuthenticationProvider"
            builder.add(provider)
            builder.build()
        then: "AuthenticationProvider is not passed into LifecycleManager (it should be managed externally)"
            0 * lm._(_ as AuthenticationProvider)
    }

    def "messages set when using WebSecurityConfigurerAdapter"() {
        when:
            loadConfig(InMemoryAuthWithWebSecurityConfigurerAdapter)
        then:
            authenticationManager.messages.messageSource instanceof ApplicationContext
    }

    def "AuthenticationEventPublisher is registered for Web registerAuthentication"() {
        when:
            loadConfig(InMemoryAuthWithWebSecurityConfigurerAdapter)
        then:
            authenticationManager.eventPublisher instanceof DefaultAuthenticationEventPublisher
    }

    @EnableWebSecurity
    @Configuration
    static class InMemoryAuthWithWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .inMemoryAuthentication()
        }
    }

    // https://github.com/SpringSource/spring-security-javaconfig/issues/132
    def "#132 Custom AuthenticationEventPublisher with Web registerAuthentication"() {
        setup:
            InMemoryAuthWithWebCustomAEPSecurityConfigurerAdapterConfig.EVENT_PUBLISHER = Mock(AuthenticationEventPublisher)
        when:
            loadConfig(InMemoryAuthWithWebCustomAEPSecurityConfigurerAdapterConfig)
        then:
            authenticationManager.eventPublisher == InMemoryAuthWithWebCustomAEPSecurityConfigurerAdapterConfig.EVENT_PUBLISHER
    }

    @EnableWebSecurity
    @Configuration
    static class InMemoryAuthWithWebCustomAEPSecurityConfigurerAdapterConfig extends WebSecurityConfigurerAdapter {
        static AuthenticationEventPublisher EVENT_PUBLISHER
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
                throws Exception {
            auth
                .authenticationEventPublisher(EVENT_PUBLISHER)
                .inMemoryAuthentication()
        }
    }
}

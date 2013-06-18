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
package org.springframework.security.config.annotation.web

import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder

import javax.servlet.http.Cookie

import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.LifecycleManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.RememberMeServices
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests for RememberMeConfigurator that flex edge cases. {@link NamespaceRememberMeTests} demonstrate mapping of the XML namespace to Java Config.
 *
 * @author Rob Winch
 */
public class RememberMeConfiguratorTests extends BaseSpringSpec {

    def "rememberMe() null UserDetailsService provides meaningful error"() {
        when: "Load Config without UserDetailsService specified"
            loadConfig(NullUserDetailsConfig)
        then: "A good error message is provided"
            Exception success = thrown()
            success.message.contains "Invoke RememberMeConfigurator#userDetailsService(UserDetailsService) or see its javadoc for alternative approaches."
    }

    @EnableWebSecurity
    @Configuration
    static class NullUserDetailsConfig extends WebSecurityConfigurerAdapter {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .authorizeUrls()
                    .anyRequest().hasRole("USER")
                    .and()
                .formLogin()
                    .and()
                .rememberMe()
        }
    }

    def "rememberMe No LogoutConfigurator"() {
        setup:
            LifecycleManager lifecycleManager = Mock()
            HttpConfiguration http = new HttpConfiguration(lifecycleManager, authenticationBldr)
            UserDetailsService uds = authenticationBldr.getDefaultUserDetailsService()
        when:
            http
                .rememberMe()
                    .userDetailsService(uds)
                    .and()
                .build()

        then:
            noExceptionThrown()
    }

    def "rememberMe LifecycleManager"() {
        setup:
            LifecycleManager lifecycleManager = Mock()
            HttpConfiguration http = new HttpConfiguration(lifecycleManager, authenticationBldr)
            UserDetailsService uds = authenticationBldr.getDefaultUserDetailsService()
        when:
            http
                .rememberMe()
                    .userDetailsService(authenticationBldr.getDefaultUserDetailsService())
                    .and()
                .build()

        then: "RememberMeAuthenticationFilter is registered with LifecycleManager"
            1 * lifecycleManager.registerLifecycle(_ as RememberMeAuthenticationFilter) >> {RememberMeAuthenticationFilter o -> o}
    }
}

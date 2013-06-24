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

import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.SecurityBuilderPostProcessor;
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.openid.OpenIDAuthenticationFilter
import org.springframework.security.openid.OpenIDAuthenticationProvider;
import org.springframework.security.openid.OpenIDAuthenticationToken

/**
 *
 * @author Rob Winch
 */
class OpenIDLoginConfigurerTests extends BaseSpringSpec {

    def "openidLogin LifecycleManager"() {
        setup:
            SecurityBuilderPostProcessor lifecycleManager = Mock()
            HttpConfiguration http = new HttpConfiguration(lifecycleManager, authenticationBldr)
            UserDetailsService uds = authenticationBldr.getDefaultUserDetailsService()
        when:
            http
                .openidLogin()
                    .authenticationUserDetailsService(new UserDetailsByNameServiceWrapper<OpenIDAuthenticationToken>(uds))
                    .and()
                .build()

        then: "OpenIDAuthenticationFilter is registered with LifecycleManager"
            1 * lifecycleManager.postProcess(_ as OpenIDAuthenticationFilter) >> {OpenIDAuthenticationFilter o -> o}
        and: "OpenIDAuthenticationProvider is registered with LifecycleManager"
            1 * lifecycleManager.postProcess(_ as OpenIDAuthenticationProvider) >> {OpenIDAuthenticationProvider o -> o}
    }
}

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

import static org.springframework.security.config.annotation.authentication.NamespacePasswordEncoderConfigs.*

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.LifecycleManager

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
            0 * lm._
    }
}

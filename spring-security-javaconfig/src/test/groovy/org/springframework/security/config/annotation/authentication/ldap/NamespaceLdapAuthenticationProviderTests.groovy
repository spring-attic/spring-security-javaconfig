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
package org.springframework.security.config.annotation.authentication.ldap

import static org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.*

import org.springframework.ldap.core.support.BaseLdapPathContextSource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.LdapAuthenticationProviderConfig;

/**
 *
 * @author Rob Winch
 *
 */
class NamespaceLdapAuthenticationProviderTests extends BaseSpringSpec {
    def "ldap-authentication-provider"() {
        when:
            loadConfig(LdapAuthenticationProviderConfig)
        then:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user","password"))
    }
}

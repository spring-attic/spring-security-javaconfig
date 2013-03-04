/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.config.annotation.authentication.ldap

import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*

import org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.test.util.ReflectionTestUtils;

/**
 *
 * @author Rob Winch
 *
 */
class LdapAuthenticationProviderBuilderSecurityBuilderTests extends BaseSpringSpec {
    def "default configuration"() {
        when:
        context = new AnnotationConfigApplicationContext(DefaultLdapConfig)
        LdapAuthenticationProvider provider = context.getBean(LdapAuthenticationProvider)
        then:
        provider.authoritiesPopulator.groupRoleAttribute == "cn"
        provider.authoritiesPopulator.groupSearchBase == "ou=groups" // TODO should this default to "" as the namespace does?
        provider.authoritiesPopulator.groupSearchFilter == "(uniqueMember={0})" // TODO should this default to "(member={0})" to match the sample as groupSearchBase is?
        ReflectionTestUtils.getField(provider,"authoritiesMapper").prefix == "ROLE_"

    }

    @Configuration
    static class DefaultLdapConfig extends BaseLdapProviderConfig {
        @Bean
        public SecurityBuilder<LdapAuthenticationProvider> authenticationProviderBuilder() {
            ldapAuthenticationProvider(contextSource());
        }
    }

    def "group roles custom"() {
        when:
        context = new AnnotationConfigApplicationContext(GroupRolesConfig)
        LdapAuthenticationProvider provider = context.getBean(LdapAuthenticationProvider)
        then:
        provider.authoritiesPopulator.groupRoleAttribute == "group"
    }

    @Configuration
    static class GroupRolesConfig extends BaseLdapProviderConfig {
        @Bean
        public SecurityBuilder<LdapAuthenticationProvider> authenticationProviderBuilder() {
            ldapAuthenticationProvider(contextSource()).groupRoleAttribute("group");
        }
    }

    def "group search custom"() {
        when:
        context = new AnnotationConfigApplicationContext(GroupSearchConfig)
        LdapAuthenticationProvider provider = context.getBean(LdapAuthenticationProvider)
        then:
        provider.authoritiesPopulator.groupSearchFilter == "ou=groupName"
    }

    @Configuration
    static class GroupSearchConfig extends BaseLdapProviderConfig {
        @Bean
        public SecurityBuilder<LdapAuthenticationProvider> authenticationProviderBuilder() {
            ldapAuthenticationProvider(contextSource()).groupSearchFilter("ou=groupName");
        }
    }

    def "role prefix custom"() {
        when:
        context = new AnnotationConfigApplicationContext(RolePrefixConfig)
        LdapAuthenticationProvider provider = context.getBean(LdapAuthenticationProvider)
        then:
        ReflectionTestUtils.getField(provider,"authoritiesMapper").prefix == "role_"
    }

    @Configuration
    static class RolePrefixConfig extends BaseLdapProviderConfig {
        @Bean
        public SecurityBuilder<LdapAuthenticationProvider> authenticationProviderBuilder() {
            ldapAuthenticationProvider(contextSource()).rolePrefix("role_")
        }
    }

    def "bind authentication"() {
        when:
        context = new AnnotationConfigApplicationContext(BindAuthenticationConfig)
        AuthenticationManager auth = context.getBean(AuthenticationManager)
        then:
        auth
        auth.authenticate(new UsernamePasswordAuthenticationToken("admin","password")).authorities.collect { it.authority }.sort() == ["ROLE_ADMIN","ROLE_USER"]
    }

    @Configuration
    static class BindAuthenticationConfig extends BaseLdapServerConfig {
        @Bean
        public SecurityBuilder<LdapAuthenticationProvider> authenticationProviderBuilder() {
            ldapAuthenticationProvider(contextSource()).userDnPatterns("uid={0},ou=people").groupSearchFilter("(member={0})");
        }
    }

    @Configuration
    static abstract class BaseLdapServerConfig extends BaseLdapProviderConfig {
        @Bean
        public ApacheDSContainer ldapServer() throws Exception {
            ApacheDSContainer apacheDSContainer = new ApacheDSContainer("dc=springframework,dc=org", "classpath:/users.ldif");
            apacheDSContainer.setPort(33389);
            return apacheDSContainer;
        }
    }

    @Configuration
    static abstract class BaseLdapProviderConfig {
        protected abstract SecurityBuilder<LdapAuthenticationProvider> authenticationProviderBuilder();

        @Bean
        public AuthenticationManager authMgr() {
            return authenticationManager(authenticationProviderBuilder()).build()
        }

        @Bean
        public AuthenticationProvider authenticationProvider() {
            return authenticationProviderBuilder().build();
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
    }
}

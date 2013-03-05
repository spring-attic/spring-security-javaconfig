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
package org.springframework.security.config.annotation.web;


import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;
import static org.springframework.security.config.annotation.SecurityExpressions.*
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*
import static org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder.*

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.BaseAuthenticationConfig;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.AntPathRequestMatcher
import org.springframework.security.web.util.AnyRequestMatcher;
import org.springframework.security.web.util.RequestMatcher

/**
 * Tests to verify that all the functionality of <http> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpTests extends BaseSpringSpec {
    def "http@access-decision-manager-ref"() {
        setup:
        AccessDecisionManagerRefConfig.ACCESS_DECISION_MGR = Mock(AccessDecisionManager)
        AccessDecisionManagerRefConfig.ACCESS_DECISION_MGR.supports(FilterInvocation) >> true
        AccessDecisionManagerRefConfig.ACCESS_DECISION_MGR.supports(_ as ConfigAttribute) >> true
        when:
        loadConfig(AccessDecisionManagerRefConfig)
        then:
        findFilter(FilterSecurityInterceptor).accessDecisionManager == AccessDecisionManagerRefConfig.ACCESS_DECISION_MGR
    }

    @Configuration
    static class AccessDecisionManagerRefConfig extends BaseWebConfig {
        static AccessDecisionManager ACCESS_DECISION_MGR

        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                    .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .accessDecisionManager(ACCESS_DECISION_MGR)
                                .permitAll())
            )
        }
    }

    def "http@access-denied-page"() {
        when:
        loadConfig(AccessDeniedPageConfig)
        then:
        findFilter(ExceptionTranslationFilter).accessDeniedHandler.errorPage == "/AccessDeniedPageConfig"
    }

    @Configuration
    static class AccessDeniedPageConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                    .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .accessDeniedPage("/AccessDeniedPageConfig")
                                .permitAll())
            )
        }
    }

    // Note that authentication-manager-ref is never implied with java config (it is required)
    def "http@authentication-manager-ref"() {
        when: "Specify AuthenticationManager"
        loadConfig(AuthenticationManagerRefConfig)
        then: "Populates the AuthenticationManager"
        findFilter(FilterSecurityInterceptor).authenticationManager
    }

    @Configuration
    static class AuthenticationManagerRefConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                    .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
            )
        }
    }

    // Note: There is no http@auto-config equivalent in Java Config

    // FIXME: Support http@create-session (need to make SessionCreationPolicy public)

    def "http@disable-url-rewriting = true (default for Java Config)"() {
        when:
        loadConfig(DefaultUrlRewritingConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).repo.disableUrlRewriting
    }

    @Configuration
    static class DefaultUrlRewritingConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                    .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
            )
        }
    }

    // http@disable-url-rewriting is on by default to disable it create a custom HttpSecurityContextRepository and use security-context-repository-ref

    def "http@disable-url-rewriting = false"() {
        when:
        loadConfig(EnableUrlRewritingConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).repo.disableUrlRewriting == false
    }

    @Configuration
    static class EnableUrlRewritingConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository()
            repository.disableUrlRewriting = false // explicitly configured (not necessary due to default values)
            new FilterChainProxySecurityBuilder()
                    .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .securityContextRepsitory(repository)
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
            )
        }
    }

    def "http@entry-point-ref"() {
        when:
        loadConfig(EntryPointRefConfig)
        then:
        findFilter(ExceptionTranslationFilter).authenticationEntryPoint.loginFormUrl == "/EntryPointRefConfig"
    }

    @Configuration
    static class EntryPointRefConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                    .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/EntryPointRefConfig"))
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
            )
        }
    }

    def "http@jaas-api-provision"() {
        when:
        loadConfig(JaasApiProvisionConfig)
        then:
        findFilter(JaasApiIntegrationFilter)
    }

    @Configuration
    static class JaasApiProvisionConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                    .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .addFilter(new JaasApiIntegrationFilter())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
            )
        }
    }

    // http@name is not available since it can be done w/ standard bean configuration easily

    def "http@once-per-request=true"() {
        when:
        loadConfig(OncePerRequestConfig)
        then:
        findFilter(FilterSecurityInterceptor).observeOncePerRequest
    }

    @Configuration
    static class OncePerRequestConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
            )
        }
    }

    // http@path-type is not available (instead request matcher instances are used)

    // http@pattern is not available (instead request matcher instances are used)

    def "http@realm"() {
        when:
        loadConfig(RealmConfig)
        then:
        findFilter(BasicAuthenticationFilter).authenticationEntryPoint.realmName == "RealmConfig"
    }

    @Configuration
    static class RealmConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
                            .apply(new HttpBasicSecurityFilterConfigurator()
                                .realmName("RealmConfig"))
                )
        }
    }

    // http@request-matcher is not available (instead request matcher instances are used)

    def "http@request-matcher-ref"() {
        when:
        loadConfig(RequestMatcherRefConfig)
        then:
        filterChain(0).requestMatcher.pattern == "/api/**"
        filterChain(1).requestMatcher.class == AnyRequestMatcher
    }

    @Configuration
    static class RequestMatcherRefConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            RequestMatcher requestMatcher = new AntPathRequestMatcher("/api/**")
            new FilterChainProxySecurityBuilder()
                .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .requestMatcher(requestMatcher) // request-matcher-ref
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll()),
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
                )
        }
    }

    def "http@security=none"() {
        when:
        loadConfig(SecurityNoneConfig)
        then:
        filterChain(0).requestMatcher.pattern == "/resources/**"
        filterChain(0).filters.empty
        filterChain(1).requestMatcher.pattern == "/public/**"
        filterChain(1).filters.empty
    }

    @Configuration
    static class SecurityNoneConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                .ignoring(antMatchers("/resources/**","/public/**")) // security=none
                .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
                )
        }
    }

    def "http@security-context-repository-ref"() {
        when:
        loadConfig(SecurityContextRepoConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).repo.class == NullSecurityContextRepository
    }

    @Configuration
    static class SecurityContextRepoConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .securityContextRepsitory(new NullSecurityContextRepository()) // security-context-repository-ref
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
                )
        }
    }

    def "http@servlet-api-provision=false"() {
        when:
        loadConfig(ServletApiProvisionConfig)
        then:
        findFilter(SecurityContextHolderAwareRequestFilter) == null
    }

    @Configuration
    static class ServletApiProvisionConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll()
                                .disableServletApiProvision(true)
                            )
                )
        }
    }

    def "http@servlet-api-provision defaults to true"() {
        when:
        loadConfig(ServletApiProvisionDefaultsConfig)
        then:
        findFilter(SecurityContextHolderAwareRequestFilter) != null
    }

    @Configuration
    static class ServletApiProvisionDefaultsConfig extends BaseWebConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr())
                                .permitAll())
                )
        }
    }

    def "http@use-expressions=false"() {
        when:
        loadConfig(DisableUseExpressionsConfig)
        then:
        findFilter(FilterSecurityInterceptor).securityMetadataSource.class == DefaultFilterInvocationSecurityMetadataSource
        findFilter(FilterSecurityInterceptor).accessDecisionManager.decisionVoters.collect { it.class } == [RoleVoter, AuthenticatedVoter]
    }

    @Configuration
    @EnableWebSecurity
    static class DisableUseExpressionsConfig extends BaseAuthenticationConfig {
        @Bean
        public FilterChainProxySecurityBuilder filterChainProxyBuilder() {
            new FilterChainProxySecurityBuilder()
                .securityFilterChains(
                    new SecurityFilterChainSecurityBuilder(authenticationMgr())
                            .apply(new DefaultSecurityFilterConfigurator(fsiSourceBldr()))
                )
        }

        protected fsiSourceBldr() {
            new FilterInvocationSecurityMetadataSourceSecurityBuilder()
                    .interceptUrl(antMatchers("/users**","/sessions/**"), "ROLE_USER")
                    .interceptUrl(antMatchers("/signup"), "ROLE_ANONYMOUS")
                    .interceptUrl(antMatchers("/**"), "ROLE_USER");
        }
    }
}

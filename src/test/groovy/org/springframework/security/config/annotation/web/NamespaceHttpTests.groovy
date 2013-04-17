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

import java.util.List;

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.AuthenticationBuilder;
import org.springframework.security.config.annotation.web.NamespaceHttpTests.AuthenticationManagerRefConfig.CustomAuthenticationManager;
import org.springframework.security.config.annotation.web.SpringSecurityFilterChainBuilder.IgnoredRequestRegistry;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
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
import org.springframework.security.web.session.SessionManagementFilter;
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

        protected void configure(HttpConfiguration http) throws Exception {
            http
                .authorizeUrls()
                    .antMatchers("/**").permitAll()
                    .accessDecisionManager(ACCESS_DECISION_MGR)
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
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .exceptionHandling()
                    .accessDeniedPage("/AccessDeniedPageConfig")
        }
    }

    def "http@authentication-manager-ref"() {
        when: "Specify AuthenticationManager"
        loadConfig(AuthenticationManagerRefConfig)
        then: "Populates the AuthenticationManager"
        findFilter(FilterSecurityInterceptor).authenticationManager.parent.class == CustomAuthenticationManager
    }

    @Configuration
    static class AuthenticationManagerRefConfig extends BaseWebConfig {
        // demo authentication-manager-ref (could be any value)
        protected AuthenticationManager authenticationManager(
                AuthenticationBuilder authenticationRegistry) throws Exception {
            return new CustomAuthenticationManager();
        }
        protected void configure(HttpConfiguration http) throws Exception {
        }

        static class CustomAuthenticationManager implements AuthenticationManager {
            public Authentication authenticate(Authentication authentication)
                    throws AuthenticationException {
                throw new BadCredentialsException("This always fails");
            }
        }
    }

    // Note: There is no http@auto-config equivalent in Java Config

    def "http@create-session=always"() {
        when:
        loadConfig(IfRequiredConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).forceEagerSessionCreation == false
        findFilter(SecurityContextPersistenceFilter).repo.allowSessionCreation == true
        findFilter(SessionManagementFilter).securityContextRepository.allowSessionCreation == true
    }

    @Configuration
    static class CreateSessionAlwaysConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.always);
        }
    }

    def "http@create-session=stateless"() {
        when:
        loadConfig(CreateSessionStatelessConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).forceEagerSessionCreation == false
        findFilter(SecurityContextPersistenceFilter).repo.class == NullSecurityContextRepository
        findFilter(SessionManagementFilter).securityContextRepository.class == NullSecurityContextRepository
    }

    @Configuration
    static class CreateSessionStatelessConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.stateless);
        }
    }

    def "http@create-session=ifRequired"() {
        when:
        loadConfig(IfRequiredConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).forceEagerSessionCreation == false
        findFilter(SecurityContextPersistenceFilter).repo.allowSessionCreation == true
        findFilter(SessionManagementFilter).securityContextRepository.allowSessionCreation == true
    }

    @Configuration
    static class IfRequiredConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.ifRequired);
        }
    }

    def "http@create-session defaults to ifRequired"() {
        when:
        loadConfig(IfRequiredConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).forceEagerSessionCreation == false
        findFilter(SecurityContextPersistenceFilter).repo.allowSessionCreation == true
        findFilter(SessionManagementFilter).securityContextRepository.allowSessionCreation == true
    }

    def "http@create-session=never"() {
        when:
        loadConfig(CreateSessionNeverConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).forceEagerSessionCreation == false
        findFilter(SecurityContextPersistenceFilter).repo.allowSessionCreation == false
        findFilter(SessionManagementFilter).securityContextRepository.allowSessionCreation == false
    }

    @Configuration
    static class CreateSessionNeverConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.never);
        }
    }

    @Configuration
    static class DefaultCreateSessionConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
        }
    }

    def "http@disable-url-rewriting = true (default for Java Config)"() {
        when:
        loadConfig(DefaultUrlRewritingConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).repo.disableUrlRewriting
    }

    @Configuration
    static class DefaultUrlRewritingConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
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
        protected void configure(HttpConfiguration http) throws Exception {
            HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository()
            repository.disableUrlRewriting = false // explicitly configured (not necessary due to default values)

            http.securityContextRepsitory(repository)
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
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/EntryPointRefConfig"))
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
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .addFilter(new JaasApiIntegrationFilter())
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
        protected void configure(HttpConfiguration http) throws Exception {}
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
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .httpBasic().realmName("RealmConfig")
        }
    }

    // http@request-matcher is not available (instead request matcher instances are used)

    def "http@request-matcher-ref"() {
        when:
        loadConfig(RequestMatcherRefConfig)
        then:
        filterChain(0).requestMatcher.pattern == "/api/**"
    }

    @Configuration
    static class RequestMatcherRefConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .antMatcher("/api/**")
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
        protected void ignoredRequests(IgnoredRequestRegistry ignoredRequests) {
            ignoredRequests
                .antMatchers("/resources/**","/public/**");
        }
        protected void configure(HttpConfiguration http) throws Exception {}
    }

    def "http@security-context-repository-ref"() {
        when:
        loadConfig(SecurityContextRepoConfig)
        then:
        findFilter(SecurityContextPersistenceFilter).repo.class == NullSecurityContextRepository
    }

    @Configuration
    static class SecurityContextRepoConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .securityContextRepsitory(new NullSecurityContextRepository()) // security-context-repository-ref
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
        protected void configure(HttpConfiguration http) throws Exception {
            http.servletApi().disable()
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
        protected void configure(HttpConfiguration http) throws Exception {
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
    static class DisableUseExpressionsConfig extends BaseWebConfig {

        protected void authorizeUrls(
                ExpressionUrlAuthorizations interceptUrls) {
        }

        protected void configure(HttpConfiguration http) throws Exception {
            http
                .apply(new UrlAuthorizations())
                    .antMatchers("/users**","/sessions/**").hasRole("USER")
                    .antMatchers("/signup").hasRole("ANONYMOUS")
                    .antMatchers("/**").hasRole("USER")
        }
    }
}

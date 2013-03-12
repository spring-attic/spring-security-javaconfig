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
package org.springframework.security.config.annotation.method;


import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*;

import static org.springframework.security.config.annotation.web.util.RequestMatchers.*;

import java.io.Serializable;

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.BaseAuthenticationConfig;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.BaseWebSpecuritySpec;
import org.springframework.security.config.annotation.method.EnableGlobalMethodSecurityTests.BaseMethodConfig;
import org.springframework.security.config.annotation.provisioning.InMemoryUserDetailsManagerSecurityBuilder
import org.springframework.security.config.annotation.web.FormLoginSecurityFilterConfiguratorTests.FormLoginConfig
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.FilterChainProxy;
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
 * Demonstrate the samples
 *
 * @author Rob Winch
 *
 */
public class SampleEnableGlobalMethodSecurityTests extends BaseSpringSpec {
    def setup() {
        SecurityContextHolder.getContext().setAuthentication(
                        new TestingAuthenticationToken("user", "password","ROLE_USER"))
    }

    def preAuthorize() {
        when:
        loadConfig(SampleWebSecurityConfig)
        MethodSecurityService service = context.getBean(MethodSecurityService)
        then:
        service.secured() == null
        service.jsr250() == null

        when:
        service.preAuthorize()
        then:
        thrown(AccessDeniedException)
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled=true)
    public static class SampleWebSecurityConfig {
        @Bean
        public MethodSecurityService methodSecurityService() {
            return new MethodSecurityServiceImpl()
        }

        @Bean
        public AuthenticationManager authenticationMgr() throws Exception {
            return inMemoryAuthentication(
                user("user").password("password").roles("USER"),
                user("admin").password("password").roles("USER", "ADMIN")
            ).authenticationManager();
        }
    }

    def 'custom permission handler'() {
        when:
        loadConfig(CustomPermissionEvaluatorWebSecurityConfig)
        MethodSecurityService service = context.getBean(MethodSecurityService)
        then:
        service.hasPermission("allowed") == null

        when:
        service.hasPermission("denied") == null
        then:
        thrown(AccessDeniedException)
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled=true)
    public static class CustomPermissionEvaluatorWebSecurityConfig extends GlobalMethodSecurityConfiguration {
        @Bean
        public MethodSecurityService methodSecurityService() {
            return new MethodSecurityServiceImpl()
        }

        @Override
        protected MethodSecurityExpressionHandler expressionHandler() {
            DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
            expressionHandler.setPermissionEvaluator(new CustomPermissionEvaluator());
            return expressionHandler;
        }

        @Bean
        public AuthenticationManager authenticationMgr() throws Exception {
            return inMemoryAuthentication(
                user("user").password("password").roles("USER"),
                user("admin").password("password").roles("USER", "ADMIN")
            ).authenticationManager();
        }
    }

    static class CustomPermissionEvaluator implements PermissionEvaluator {
        public boolean hasPermission(Authentication authentication,
                Object targetDomainObject, Object permission) {
            return !"denied".equals(targetDomainObject);
        }

        public boolean hasPermission(Authentication authentication,
                Serializable targetId, String targetType, Object permission) {
            return !"denied".equals(targetId);
        }

    }
}

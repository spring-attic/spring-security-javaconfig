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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.NamespaceHttpTests.AuthenticationManagerRefConfig.CustomAuthenticationManager
import org.springframework.security.config.annotation.web.NamespaceHttpTests.RequestMatcherRefConfig.MyRequestMatcher
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.NullRequestCache
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.security.web.session.SessionManagementFilter
import org.springframework.security.web.util.RegexRequestMatcher
import org.springframework.security.web.util.RequestMatcher
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * HttpConfiguration tests
 *
 * @author Rob Winch
 *
 */
public class HttpConfigurationTests extends BaseSpringSpec {
    def "addFilter with unregistered Filter"() {
        when:
            loadConfig(UnregisteredFilterConfig)
        then:
            BeanCreationException success = thrown()
            success.message.contains "The Filter class ${UnregisteredFilter.name} does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead."
    }

    @Configuration
    static class UnregisteredFilterConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .addFilter(new UnregisteredFilter())
        }
    }

    static class UnregisteredFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            filterChain.doFilter(request, response);
        }
    }

    // https://github.com/SpringSource/spring-security-javaconfig/issues/104
    def "#104 addFilter CasAuthenticationFilter"() {
        when:
            loadConfig(CasAuthenticationFilterConfig)
        then:
            findFilter(CasAuthenticationFilter)
    }

    @Configuration
    static class CasAuthenticationFilterConfig extends BaseWebConfig {
        protected void configure(HttpConfiguration http) throws Exception {
            http
                .addFilter(new CasAuthenticationFilter())
        }
    }
}

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
package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.spockframework.util.Assert;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.RequestMatcher;

/**
 * @author Rob Winch
 * @since 3.2
 */
public class ExpressionUrlAuthorizationRegistry extends BaseInterceptUrlConfigurator<ExpressionUrlAuthorizationRegistry.AuthorizedUrl> {
    public static final String permitAll = "permitAll";
    public static final String authenticated = "authenticated";
    public static final String fullyAuthenticated = "fullyAuthenticated";

    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();

    public ExpressionUrlAuthorizationRegistry expressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
        this.expressionHandler = expressionHandler;
        return this;
    }

    AuthorizedUrl chainRequestMatchers(List<RequestMatcher> requestMatchers) {
        return new AuthorizedUrl(requestMatchers);
    }

    private ExpressionUrlAuthorizationRegistry interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, Collection<ConfigAttribute> configAttributes) {
        for(RequestMatcher requestMatcher : requestMatchers) {
            addMapping(new UrlMapping(requestMatcher, configAttributes));
        }
        return this;
    }

    final List<AccessDecisionVoter> decisionVoters() {
        List<AccessDecisionVoter> decisionVoters = new ArrayList<AccessDecisionVoter>();
        WebExpressionVoter expressionVoter = new WebExpressionVoter();
        expressionVoter.setExpressionHandler(expressionHandler);
        decisionVoters.add(expressionVoter);
        return decisionVoters;
    }

    ExpressionBasedFilterInvocationSecurityMetadataSource createMetadataSource() {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = createRequestMap();
        return requestMap.isEmpty() ? null : new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, expressionHandler);
    }

    public static String hasRole(String role) {
        Assert.notNull(role, "role cannot be null");
        if (role.startsWith("ROLE_")) {
            throw new IllegalArgumentException("role should not start with 'ROLE_' since it is automatically inserted. Got '" + role + "'");
        }
        return "hasRole('ROLE_" + role + "')";
    }

    public static String hasAuthority(String authority) {
        return "hasAuthority('" + authority + "')";
    }

    public static String hasAnyAuthority(String... authorities) {
        String anyAuthorities = StringUtils.join(authorities, "','");
        return "hasAnyAuthority('" + anyAuthorities + "')";
    }

    public class AuthorizedUrl {
        private List<RequestMatcher> requestMatchers;

        private AuthorizedUrl(List<RequestMatcher> requestMatchers) {
            this.requestMatchers = requestMatchers;
        }

        public ExpressionUrlAuthorizationRegistry hasRole(String role) {
            return configAttribute(ExpressionUrlAuthorizationRegistry.hasRole(role));
        }

        public ExpressionUrlAuthorizationRegistry hasAuthority(String authority) {
            return configAttribute(ExpressionUrlAuthorizationRegistry.hasAuthority(authority));
        }

        public ExpressionUrlAuthorizationRegistry hasAnyAuthority(String... authorities) {
            return configAttribute(ExpressionUrlAuthorizationRegistry.hasAnyAuthority(authorities));
        }

        public ExpressionUrlAuthorizationRegistry permitAll() {
            return configAttribute(permitAll);
        }

        public ExpressionUrlAuthorizationRegistry authenticated() {
            return configAttribute(authenticated);
        }

        public ExpressionUrlAuthorizationRegistry fullyAuthenticated() {
            return configAttribute(fullyAuthenticated);
        }

        public ExpressionUrlAuthorizationRegistry configAttribute(String attribute) {
            interceptUrl(requestMatchers, SecurityConfig.createList(attribute));
            return ExpressionUrlAuthorizationRegistry.this;
        }
    }
}
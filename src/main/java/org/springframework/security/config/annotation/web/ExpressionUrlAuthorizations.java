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

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Rob Winch
 * @since 3.2
 */
public class ExpressionUrlAuthorizations extends BaseInterceptUrlConfigurator<ExpressionUrlAuthorizations.AuthorizedUrl> {
    public static final String permitAll = "permitAll";
    public static final String denyAll = "denyAll";
    public static final String anonymous = "anonymous";
    public static final String authenticated = "authenticated";
    public static final String fullyAuthenticated = "fullyAuthenticated";
    public static final String rememberMe = "rememberMe";

    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();

    public ExpressionUrlAuthorizations expressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
        this.expressionHandler = expressionHandler;
        return this;
    }

    AuthorizedUrl chainRequestMatchers(List<RequestMatcher> requestMatchers) {
        return new AuthorizedUrl(requestMatchers);
    }

    private ExpressionUrlAuthorizations interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, Collection<ConfigAttribute> configAttributes) {
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
        String anyAuthorities = StringUtils.arrayToDelimitedString(authorities, "','");
        return "hasAnyAuthority('" + anyAuthorities + "')";
    }

    public static String hasIpAddress(String ipAddressExpression) {
        return "hasIpAddress('" + ipAddressExpression + "')";
    }

    public class AuthorizedUrl {
        private List<RequestMatcher> requestMatchers;

        private AuthorizedUrl(List<RequestMatcher> requestMatchers) {
            this.requestMatchers = requestMatchers;
        }

        public ExpressionUrlAuthorizations hasRole(String role) {
            return access(ExpressionUrlAuthorizations.hasRole(role));
        }

        public ExpressionUrlAuthorizations hasAuthority(String authority) {
            return access(ExpressionUrlAuthorizations.hasAuthority(authority));
        }

        public ExpressionUrlAuthorizations hasAnyAuthority(String... authorities) {
            return access(ExpressionUrlAuthorizations.hasAnyAuthority(authorities));
        }

        public ExpressionUrlAuthorizations hasIpAddress(String ipaddressExpression) {
            return access(ExpressionUrlAuthorizations.hasIpAddress(ipaddressExpression));
        }

        public ExpressionUrlAuthorizations permitAll() {
            return access(permitAll);
        }

        public ExpressionUrlAuthorizations anonymous() {
            return access(anonymous);
        }

        public ExpressionUrlAuthorizations rememberMe() {
            return access(rememberMe);
        }

        public ExpressionUrlAuthorizations denyAll() {
            return access(denyAll);
        }

        public ExpressionUrlAuthorizations authenticated() {
            return access(authenticated);
        }

        public ExpressionUrlAuthorizations fullyAuthenticated() {
            return access(fullyAuthenticated);
        }

        public ExpressionUrlAuthorizations access(String attribute) {
            interceptUrl(requestMatchers, SecurityConfig.createList(attribute));
            return ExpressionUrlAuthorizations.this;
        }
    }
}
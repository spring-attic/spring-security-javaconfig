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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.ConsensusBased;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.RequestMatcher;

/**
 * @author Rob Winch
 * @since 3.2
 */
public class ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder extends BaseFilterInvocationSecurityMetadataSourceSecurityBuilder {
    public static final String permitAll = "permitAll";
    public static final String authenticated = "authenticated";
    public static final String fullyAuthenticated = "fullyAuthenticated";

    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();

    public ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder expressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
        this.expressionHandler = expressionHandler;
        return this;
    }


    /**
     * @param string
     * @return
     */
    public ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder authenticated(
            List<RequestMatcher> requestMatchers) {
        return interceptUrl(requestMatchers, SecurityConfig.createList(authenticated));
    }

    public ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder hasRole(List<RequestMatcher> requestMatchers, String role) {
        return interceptUrl(requestMatchers, SecurityConfig.createList(hasRole(role)));
    }

    public ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder permitAll(List<RequestMatcher> requestMatchers) {
        return interceptUrl(requestMatchers, SecurityConfig.createList(permitAll));
    }

    public ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder hasAuthority(List<RequestMatcher> requestMatchers, String authority) {
        return interceptUrl(requestMatchers, SecurityConfig.createList(hasAuthority(authority)));
    }

    public ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder hasAnyAuthority(List<RequestMatcher> requestMatchers, String... authorities) {
        return interceptUrl(requestMatchers, SecurityConfig.createList(hasAnyAuthority(authorities)));
    }

    public ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder interceptUrl(RequestMatcher requestMatcher, String configAttribute) {
        return interceptUrl(Arrays.asList(requestMatcher), SecurityConfig.createList(configAttribute));
    }

    public ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, String configAttribute) {
        return interceptUrl(requestMatchers, SecurityConfig.createList(configAttribute));
    }

    private ExpressionFilterInvocationSecurityMetadataSourceSecurityBuilder interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, Collection<ConfigAttribute> configAttributes) {
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

    public ExpressionBasedFilterInvocationSecurityMetadataSource build() {
        return new ExpressionBasedFilterInvocationSecurityMetadataSource(createRequestMap(), expressionHandler);
    }

    public static String hasRole(String role) {
        return "hasRole('ROLE_" + role + "')";
    }

    public static String hasAuthority(String authority) {
        return "hasAuthority('" + authority + "')";
    }

    public static String hasAnyAuthority(String... authorities) {
        String anyAuthorities = StringUtils.join(authorities, "','");
        return "hasAnyAuthority('" + anyAuthorities + "')";
    }

}

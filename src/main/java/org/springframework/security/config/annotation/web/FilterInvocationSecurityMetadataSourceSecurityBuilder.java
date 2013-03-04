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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.ConsensusBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class FilterInvocationSecurityMetadataSourceSecurityBuilder implements SecurityBuilder<FilterInvocationSecurityMetadataSource> {
    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();
    private List<UrlMapping> urlMappings = new ArrayList<UrlMapping>();
    private boolean disableExpressions;

    public FilterInvocationSecurityMetadataSourceSecurityBuilder expressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
        this.expressionHandler = expressionHandler;
        return this;
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder disableExpressions(boolean disableExpressions) {
        this.disableExpressions = disableExpressions;
        return this;
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder insertAntInterceptUrl(String pattern, String... configAttributes) {
        return insertInterceptUrl(antMatchers(pattern), SecurityConfig.createList(configAttributes));
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder insertAntInterceptUrl(String pattern, Iterable<? extends ConfigAttribute> configAttributes) {
        return interceptUrl(antMatchers(pattern), configAttributes);
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder insertInterceptUrl(Iterable<? extends RequestMatcher> requestMatchers, String... configAttributes) {
        return interceptUrl(requestMatchers, SecurityConfig.createList(configAttributes));
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder insertInterceptUrl(Iterable<? extends RequestMatcher> requestMatchers, Iterable<? extends ConfigAttribute> configAttributes) {
        return insertInterceptUrlAt(requestMatchers, configAttributes, 1);
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder antInterceptUrl(String pattern, String... configAttributes) {
        return interceptUrl(antMatchers(pattern), SecurityConfig.createList(configAttributes));
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder antInterceptUrl(String pattern, Iterable<? extends ConfigAttribute> configAttributes) {
        return interceptUrl(antMatchers(pattern), configAttributes);
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder interceptUrl(RequestMatcher requestMatcher, String... configAttributes) {
        return interceptUrl(Arrays.asList(requestMatcher), SecurityConfig.createList(configAttributes));
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, String... configAttributes) {
        return interceptUrl(requestMatchers, SecurityConfig.createList(configAttributes));
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, Iterable<? extends ConfigAttribute> configAttributes) {
        return insertInterceptUrlAt(requestMatchers, configAttributes, urlMappings.size());
    }

    final AccessDecisionManager createDefaultAccessDecisionManager() {
        List<AccessDecisionVoter> decisionVoters = new ArrayList<AccessDecisionVoter>();
        if(disableExpressions) {
            decisionVoters.add(new RoleVoter());
            decisionVoters.add(new AuthenticatedVoter());
        } else {
            WebExpressionVoter expressionVoter = new WebExpressionVoter();
            expressionVoter.setExpressionHandler(expressionHandler);
            decisionVoters.add(expressionVoter);
        }
        return new ConsensusBased(decisionVoters);
    }

    private FilterInvocationSecurityMetadataSourceSecurityBuilder insertInterceptUrlAt(Iterable<? extends RequestMatcher> requestMatchers, Iterable<? extends ConfigAttribute> configAttributes, int location) {
        List<ConfigAttribute> configAttrs = new ArrayList<ConfigAttribute>();
        for(ConfigAttribute attr : configAttributes) {
            configAttrs.add(attr);
        }
        for(RequestMatcher matcher : requestMatchers) {
            urlMappings.add(location,new UrlMapping(matcher,configAttrs));
        }
        return this;
    }

    public FilterInvocationSecurityMetadataSource build() {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher,Collection<ConfigAttribute>>();
        for(UrlMapping mapping : urlMappings) {
            requestMap.put(mapping.requestMatcher, mapping.configAttrs);
        }
        return disableExpressions ? new DefaultFilterInvocationSecurityMetadataSource(requestMap) : new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, expressionHandler);
    }

    public static List<AntPathRequestMatcher> antMatchers(HttpMethod httpMethod, String...antPatterns) {
        String method = httpMethod == null ? null : httpMethod.toString();
        List<AntPathRequestMatcher> matchers = new ArrayList<AntPathRequestMatcher>();
        for(String pattern : antPatterns) {
            matchers.add(new AntPathRequestMatcher(pattern, method));
        }
        return matchers;
    }

    public static List<AntPathRequestMatcher> antMatchers(String...antPatterns) {
        return antMatchers(null, antPatterns);
    }

    private static class UrlMapping {
        private RequestMatcher requestMatcher;
        private Collection<ConfigAttribute> configAttrs;

        public UrlMapping(RequestMatcher requestMatcher, Collection<ConfigAttribute> configAttrs) {
            this.requestMatcher = requestMatcher;
            this.configAttrs = configAttrs;
        }
    }
}

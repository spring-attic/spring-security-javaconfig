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
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.RequestMatcher;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class FilterInvocationSecurityMetadataSourceSecurityBuilder extends BaseFilterInvocationSecurityMetadataSourceSecurityBuilder implements SecurityBuilder<FilterInvocationSecurityMetadataSource> {

    public FilterInvocationSecurityMetadataSourceSecurityBuilder interceptUrl(RequestMatcher requestMatcher, String... configAttributes) {
        return interceptUrl(Arrays.asList(requestMatcher), SecurityConfig.createList(configAttributes));
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, String... configAttributes) {
        return interceptUrl(requestMatchers, SecurityConfig.createList(configAttributes));
    }

    public FilterInvocationSecurityMetadataSourceSecurityBuilder interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, Collection<ConfigAttribute> configAttributes) {
        for(RequestMatcher requestMatcher : requestMatchers) {
            addMapping(new UrlMapping(requestMatcher, configAttributes));
        }
        return this;
    }

    final List<AccessDecisionVoter> decisionVoters() {
        List<AccessDecisionVoter> decisionVoters = new ArrayList<AccessDecisionVoter>();
        decisionVoters.add(new RoleVoter());
        decisionVoters.add(new AuthenticatedVoter());
        return decisionVoters;
    }

    public FilterInvocationSecurityMetadataSource build() {
        return new DefaultFilterInvocationSecurityMetadataSource(createRequestMap());
    }
}

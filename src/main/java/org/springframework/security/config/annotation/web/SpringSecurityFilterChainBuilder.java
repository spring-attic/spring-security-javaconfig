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
import java.util.List;

import org.springframework.security.config.annotation.AbstractSecurityBuilder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class SpringSecurityFilterChainBuilder extends AbstractSecurityBuilder<FilterChainProxy> {
    private List<RequestMatcher> ignoredRequests = new ArrayList<RequestMatcher>();
    private List<HttpConfigurator> httpBuilders = new ArrayList<HttpConfigurator>();
    private FilterSecurityInterceptor filterSecurityInterceptor;
    private HttpFirewall httpFirewall;
    private final IgnoredRequestRegistry ignoredRequestRegistry = new IgnoredRequestRegistry();

    // TODO change this to SecurityBuilder<SecurityFilterChain> when we eliminate the need for creating a global WebInvocationPrivilegeEvaluator
    public SpringSecurityFilterChainBuilder securityFilterChains(HttpConfigurator... httpBuilders) {
        this.httpBuilders.addAll(Arrays.asList(httpBuilders));
        return this;
    }

    protected FilterChainProxy doBuild() throws Exception {
        Assert.state(!httpBuilders.isEmpty(), "At least one SecurityFilterBuilder needs to be specified. Invoke FilterChainProxyBuilder.securityFilterChains");
        int chainSize = ignoredRequests.size() + httpBuilders.size();
        List<SecurityFilterChain> securityFilterChains = new ArrayList<SecurityFilterChain>(chainSize);
        for(RequestMatcher ignoredRequest : ignoredRequests) {
            securityFilterChains.add(new DefaultSecurityFilterChain(ignoredRequest));
        }
        for(HttpConfigurator http : httpBuilders) {
            securityFilterChains.add(http.build());
            this.filterSecurityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
        }
        FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
        if(httpFirewall != null) {
            filterChainProxy.setFirewall(httpFirewall);
        }
        return filterChainProxy;
    }

    public SpringSecurityFilterChainBuilder httpFirewall(HttpFirewall httpFirewall) {
        this.httpFirewall = httpFirewall;
        return this;
    }

    public IgnoredRequestRegistry ignoring() {
        return ignoredRequestRegistry;
    }

    public final class IgnoredRequestRegistry extends BaseRequestMatcherRegistry<IgnoredRequestRegistry,FilterChainProxy,SpringSecurityFilterChainBuilder> {

        IgnoredRequestRegistry chainRequestMatchers(List<RequestMatcher> requestMatchers) {
            ignoredRequests.addAll(requestMatchers);
            return this;
        }

        public SpringSecurityFilterChainBuilder and() {
            return SpringSecurityFilterChainBuilder.this;
        }

        private IgnoredRequestRegistry(){}
    }

    public FilterSecurityInterceptor securityInterceptor() {
        return filterSecurityInterceptor;
    }

}
